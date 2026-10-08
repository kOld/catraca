<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use Symfony\Component\Process\Process;
use Throwable;

use function array_is_list;
use function file_get_contents;
use function in_array;
use function is_array;
use function is_executable;
use function is_int;
use function is_string;
use function json_decode;
use function json_last_error;
use function sprintf;
use function str_starts_with;
use function sys_get_temp_dir;
use function tempnam;
use function trim;
use function unlink;

/**
 * Scans the repository for hardcoded secrets using gitleaks.
 *
 * Gitleaks is an optional, git-aware, cross-language secret scanner. When the
 * binary is not installed the scan is skipped silently, matching catraca's
 * `missing_tool: skip` policy. Standard noise paths (third-party code, caches,
 * VCS metadata) are filtered out of the findings so they never block the gate.
 *
 * The consumer project controls detection rules and allowlists through its own
 * `.gitleaks.toml` at the repository root; catraca auto-discovers it via
 * gitleaks' `--source` config lookup. The source is passed as `.` from the
 * repository working directory so allowlist paths remain relative and stable.
 *
 * @see https://github.com/gitleaks/gitleaks
 */
final class GitleaksScanner
{
    /** Paths whose contents are third-party or generated and must never block the gate. */
    private const array EXCLUDED_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
    ];

    public function __construct(
        private readonly string $root,
    ) {}

    /** @return array<int, string> */
    public function scan(): array
    {
        $binary = $this->resolveBinary('gitleaks');
        if ($binary === null) {
            return [];
        }

        $reportPath = tempnam(sys_get_temp_dir(), 'catraca-gitleaks-');
        if ($reportPath === false) {
            return [$this->failure('could not create a report file', null)];
        }

        $process = new Process(
            [
                $binary,
                'detect',
                '--no-git',
                '--no-banner',
                '--redact',
                '--report-format',
                'json',
                '--report-path',
                $reportPath,
                '--source',
                '.',
            ],
            $this->root,
            timeout: 180,
        );
        try {
            $process->run();
        } catch (Throwable $exception) {
            @unlink($reportPath);

            return [$this->failure('could not run', null)];
        }

        $exitCode = $process->getExitCode();
        $raw = @file_get_contents($reportPath);
        @unlink($reportPath);

        if (!in_array($exitCode, [0, 1], true)) {
            return [$this->failure('exited', $exitCode)];
        }

        if (!is_string($raw)) {
            return [$this->failure('returned no report', $exitCode)];
        }

        $raw = trim($raw);
        $report = json_decode($raw, true);
        if (
            $raw === ''
            || !str_starts_with($raw, '[')
            || !is_array($report)
            || !array_is_list($report)
            || json_last_error() !== JSON_ERROR_NONE
        ) {
            return [$this->failure('returned invalid JSON', $exitCode)];
        }

        if ($exitCode === 1 && $report === []) {
            return [$this->failure('exited', $exitCode)];
        }

        $findings = [];
        foreach ($report as $item) {
            if (!is_array($item)) {
                return [$this->failure('returned an invalid report', $exitCode)];
            }

            $file = $item['File'] ?? null;
            if (!is_string($file) || $file === '') {
                return [$this->failure('returned an invalid report', $exitCode)];
            }

            $rule = $item['RuleID'] ?? null;
            $line = $item['StartLine'] ?? null;
            $description = $item['Description'] ?? null;
            if (
                !is_string($rule)
                || trim($rule) === ''
                || !is_int($line)
                || $line < 1
                || !is_string($description)
                || trim($description) === ''
            ) {
                return [$this->failure('returned an invalid report', $exitCode)];
            }

            // gitleaks may report absolute paths when --source is absolute;
            // normalize to relative so the exclude filter and output stay clean
            $rootPrefix = $this->root . '/';
            if (str_starts_with($file, $rootPrefix)) {
                $file = substr($file, strlen($rootPrefix));
            }
            if ($file === '' || $this->isExcludedPath($file)) {
                continue;
            }

            $findings[] = sprintf('[gitleaks:%s] %s:%d %s', $rule, $file, $line, $description);
        }

        return $findings;
    }

    private function failure(string $reason, ?int $exitCode): string
    {
        $status = $exitCode === null ? 'unknown' : (string) $exitCode;

        return "gitleaks {$reason} with status {$status}";
    }

    /**
     * Resolves an optional external binary: prefers a project-local
     * `vendor/bin/<name>`, then falls back to `$PATH` via `which`.
     */
    private function resolveBinary(string $name): ?string
    {
        $local = $this->root . '/vendor/bin/' . $name;
        if (is_executable($local)) {
            return $local;
        }

        try {
            $which = new Process(['which', $name]);
            $which->run();
        } catch (Throwable) {
            return null;
        }

        if (!$which->isSuccessful()) {
            return null;
        }

        $path = trim($which->getOutput());

        return $path === '' ? null : $path;
    }

    private function isExcludedPath(string $relativeFile): bool
    {
        foreach (self::EXCLUDED_PATHS as $exclude) {
            if ($relativeFile === $exclude || str_starts_with($relativeFile, $exclude . '/')) {
                return true;
            }
        }

        return false;
    }
}
