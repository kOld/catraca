<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use Symfony\Component\Process\Process;
use Throwable;

use function array_is_list;
use function array_key_exists;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_last_error;
use function json_last_error_msg;
use function preg_replace;
use function strtolower;
use function substr;
use function trim;

/**
 * Runs package-manager audits and converts their reports into gate findings.
 *
 * Composer and npm both use non-zero exit codes for valid vulnerability
 * reports. This boundary validates the report shape before interpreting the
 * severity so process failures and malformed tool output cannot look clean.
 */
final class DependencyAuditScanner
{
    private const array COMPOSER_SEVERITIES = [
        'low',
        'medium',
        'moderate',
        'high',
        'critical',
    ];

    private const array NPM_SEVERITIES = [
        'none',
        'info',
        'low',
        'moderate',
        'high',
        'critical',
    ];

    public function __construct(
        private readonly string $root,
    ) {}

    /**
     * @return array{findings: array<int, string>, critical: int}
     */
    public function runComposerAudit(string $composerBin): array
    {
        try {
            $process = new Process([$composerBin, 'audit', '--format=json'], timeout: 120);
            $process->setWorkingDirectory($this->root);
            $process->run();
        } catch (Throwable $exception) {
            return $this->composerFailure(null, 'could not run', $exception->getMessage());
        }

        $exitCode = $process->getExitCode();
        if (!in_array($exitCode, [0, 1, 2, 3], true)) {
            return $this->composerFailure($exitCode, 'exited', $process->getErrorOutput());
        }

        $output = trim($process->getOutput());
        $data = json_decode($output, true);
        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            $diagnostic = json_last_error_msg() . ' ' . trim($process->getErrorOutput());

            return $this->composerFailure($exitCode, 'returned invalid JSON', $diagnostic);
        }

        if (!array_key_exists('advisories', $data) || !is_array($data['advisories'])) {
            return $this->composerFailure($exitCode, 'returned an invalid advisory payload');
        }

        $hasAbandoned = array_key_exists('abandoned', $data);
        $abandoned = $data['abandoned'] ?? null;
        if ($hasAbandoned && !is_array($abandoned)) {
            return $this->composerFailure($exitCode, 'returned an invalid abandoned package payload');
        }

        if ($exitCode >= 2 && (!is_array($abandoned) || $abandoned === [])) {
            return $this->composerFailure($exitCode, 'returned an invalid abandoned package payload');
        }

        $hasFilter = array_key_exists('filter', $data);
        $filter = $data['filter'] ?? null;
        $filterCount = 0;
        if ($hasFilter) {
            if (!is_array($filter)) {
                return $this->composerFailure($exitCode, 'returned an invalid policy payload');
            }

            foreach ($filter as $package => $entries) {
                if (!is_string($package) || !is_array($entries) || !array_is_list($entries)) {
                    return $this->composerFailure($exitCode, 'returned an invalid policy payload');
                }

                foreach ($entries as $entry) {
                    if (!is_array($entry)) {
                        return $this->composerFailure($exitCode, 'returned an invalid policy payload');
                    }

                    $filterCount++;
                }
            }
        }

        $hasUnreachable = array_key_exists('unreachable-repositories', $data);
        $unreachable = $data['unreachable-repositories'] ?? null;
        if ($hasUnreachable && (!is_array($unreachable) || !array_is_list($unreachable))) {
            return $this->composerFailure($exitCode, 'returned an invalid repository payload');
        }
        if ($hasUnreachable) {
            foreach ($unreachable as $repository) {
                if (!is_string($repository)) {
                    return $this->composerFailure($exitCode, 'returned an invalid repository payload');
                }
            }
        }

        $advisories = $this->parseComposerAdvisories($data['advisories']);
        if ($advisories === null) {
            return $this->composerFailure($exitCode, 'returned an invalid advisory payload');
        }

        $criticalCount = 0;
        $findings = [];

        foreach ($advisories as $advisory) {
            $severity = strtolower((string) $advisory['severity']);
            // Valid lower-severity advisories remain nonblocking for this gate.
            if (!in_array($severity, ['critical', 'high'], true)) {
                continue;
            }

            $criticalCount++;
            $title = is_string($advisory['title'] ?? null) ? $advisory['title'] : 'unknown';
            $cve = is_string($advisory['cve'] ?? null) ? $advisory['cve'] : 'N/A';
            $findings[] = "{$title} ({$cve})";
        }

        $hasAbandonedFindings = is_array($abandoned) && $abandoned !== [];
        if ($hasAbandonedFindings) {
            $findings[] = 'composer audit reported abandoned package policy findings';
        }

        if ($filterCount > 0) {
            $findings[] = 'composer audit reported dependency policy findings';
        }

        if ($unreachable !== null && $unreachable !== []) {
            $findings[] = 'composer audit could not reach dependency policy repositories';
        }

        if ($exitCode === 1 && $findings === [] && $advisories === [] && $filterCount === 0 && !$hasAbandonedFindings) {
            return $this->composerFailure($exitCode, 'reported no audit findings');
        }

        return ['findings' => $findings, 'critical' => $criticalCount];
    }

    /** @return array<int, string> */
    public function checkNpmAudit(): array
    {
        if (!is_file($this->root . '/package.json')) {
            return [];
        }

        if (!is_file($this->root . '/package-lock.json')) {
            $unsupportedLock = is_file($this->root . '/yarn.lock')
                ? 'yarn.lock'
                : (is_file($this->root . '/pnpm-lock.yaml') ? 'pnpm-lock.yaml' : null);
            $reason = $unsupportedLock === null
                ? 'cannot run without package-lock.json'
                : "cannot run against unsupported {$unsupportedLock}";

            return [$this->auditFailure('npm', null, $reason, '')];
        }

        try {
            $whichNpm = new Process(['which', 'npm']);
            $whichNpm->run();
        } catch (Throwable) {
            return [];
        }

        $npmBin = trim($whichNpm->getOutput());
        if (!$whichNpm->isSuccessful() || $npmBin === '') {
            return [];
        }

        try {
            $process = new Process([$npmBin, 'audit', '--json'], $this->root, timeout: 120);
            $process->run();
        } catch (Throwable $exception) {
            return [$this->auditFailure('npm', null, 'could not run', $exception->getMessage())];
        }

        $exitCode = $process->getExitCode();
        if (!in_array($exitCode, [0, 1], true)) {
            return [$this->auditFailure('npm', $exitCode, 'exited', $process->getErrorOutput())];
        }

        $output = trim($process->getOutput());
        $data = json_decode($output, true);
        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            return [$this->auditFailure('npm', $exitCode, 'returned invalid JSON', json_last_error_msg())];
        }

        $vulnerabilities = $data['vulnerabilities'] ?? null;
        if (!is_array($vulnerabilities)) {
            return [$this->auditFailure('npm', $exitCode, 'returned an invalid vulnerability payload', '')];
        }

        $findings = [];
        foreach ($vulnerabilities as $name => $vuln) {
            if (!is_string($name) || !is_array($vuln)) {
                return [$this->auditFailure('npm', $exitCode, 'returned an invalid vulnerability entry', '')];
            }

            $severity = $vuln['severity'] ?? null;
            if (!is_string($severity) || !in_array(strtolower($severity), self::NPM_SEVERITIES, true)) {
                return [$this->auditFailure('npm', $exitCode, 'returned an invalid vulnerability severity', '')];
            }

            if (in_array(strtolower($severity), ['critical', 'high'], true)) {
                $via = $vuln['via'] ?? [];
                $title = $name;
                if (is_array($via)) {
                    foreach ($via as $v) {
                        if (is_array($v) && is_string($v['title'] ?? null)) {
                            $title = $v['title'];
                            break;
                        }
                    }
                }
                $findings[] = '[' . strtolower($severity) . "] {$name}: {$title}";
            }
        }

        if ($exitCode === 1 && $vulnerabilities === []) {
            return [$this->auditFailure('npm', $exitCode, 'reported no audit findings', '')];
        }

        return $findings;
    }

    /**
     * @param  array<mixed>  $payload
     * @return array<int, array<string, mixed>>|null
     */
    private function parseComposerAdvisories(array $payload): ?array
    {
        /** @var array<int, array<string, mixed>> $entries */
        $entries = [];
        if (array_is_list($payload)) {
            foreach ($payload as $advisory) {
                if (!is_array($advisory) || ($advisory = $this->normalizeComposerAdvisory($advisory)) === null) {
                    return null;
                }

                $entries[] = $advisory;
            }

            return $entries;
        }

        foreach ($payload as $package => $packageAdvisories) {
            if (!is_string($package) || !is_array($packageAdvisories) || !array_is_list($packageAdvisories)) {
                return null;
            }

            foreach ($packageAdvisories as $advisory) {
                if (!is_array($advisory) || ($advisory = $this->normalizeComposerAdvisory($advisory)) === null) {
                    return null;
                }

                $entries[] = $advisory;
            }
        }

        return $entries;
    }

    /**
     * @param  array<mixed>  $advisory
     * @return array<string, mixed>|null
     */
    private function normalizeComposerAdvisory(array $advisory): ?array
    {
        $severity = $advisory['severity'] ?? null;
        if (!is_string($severity) || !in_array(strtolower($severity), self::COMPOSER_SEVERITIES, true)) {
            return null;
        }

        foreach (['title', 'advisoryId'] as $field) {
            if (array_key_exists($field, $advisory) && !is_string($advisory[$field])) {
                return null;
            }
        }

        if (array_key_exists('cve', $advisory) && $advisory['cve'] !== null && !is_string($advisory['cve'])) {
            return null;
        }

        /** @var array<string, mixed> $normalized */
        $normalized = [];
        foreach ($advisory as $key => $value) {
            if (!is_string($key)) {
                return null;
            }

            $normalized[$key] = $value;
        }

        return $normalized;
    }

    private function auditFailure(string $tool, ?int $exitCode, string $reason, string $diagnostic): string
    {
        $status = $exitCode === null ? 'unknown' : (string) $exitCode;
        $diagnostic = $this->redactDiagnostic($diagnostic);
        $suffix = $diagnostic === '' ? '' : ': ' . $diagnostic;

        return "{$tool} audit {$reason} with status {$status}{$suffix}";
    }

    /**
     * @return array{findings: array<int, string>, critical: int}
     */
    private function composerFailure(?int $exitCode, string $reason, string $diagnostic = ''): array
    {
        return [
            'findings' => [$this->auditFailure('composer', $exitCode, $reason, $diagnostic)],
            'critical' => 0,
        ];
    }

    private function redactDiagnostic(string $diagnostic): string
    {
        $diagnostic = trim($diagnostic);
        if ($diagnostic === '') {
            return '';
        }

        $diagnostic = (string) preg_replace('~(https?://)[^/\s:@]+(?::[^@\s]*)?@~i', '$1[redacted]@', $diagnostic);

        $diagnostic = (string) preg_replace(
            '~(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s]+~i',
            '$1[redacted]',
            $diagnostic,
        );

        $diagnostic = (string) preg_replace(
            '/(?i)(password|secret|token|api[_-]?key|private[_-]?key)([=: ]+)\S+/',
            '$1$2[redacted]',
            $diagnostic,
        );

        return substr($diagnostic, 0, 240);
    }
}
