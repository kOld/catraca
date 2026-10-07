<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\ActionType;
use B7S\Catraca\Enum\Severity;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\GateInterface;
use B7S\Catraca\GateResult;
use B7S\Catraca\SourcePathResolver;
use B7S\Catraca\ToolResolver;
use RuntimeException;
use Symfony\Component\Process\Process;

use function array_slice;
use function count;
use function file_exists;
use function file_get_contents;
use function is_array;
use function is_int;
use function is_numeric;
use function is_string;
use function sprintf;
use function str_contains;

class ComplexityGate implements GateInterface
{
    private const int BLOCK_AT = 50;

    private const int WARN_AT = 20;

    public function run(Baseline $baseline, ToolResolver $resolver): GateResult
    {
        $phpmetrics = $resolver->resolve('phpmetrics');
        if ($phpmetrics === null) {
            return new GateResult(
                status: Status::Skip,
                name: 'complexity',
                label: 'Cyclomatic Complexity',
                message: 'phpmetrics not found (install phpmetrics/phpmetrics)',
                severity: Severity::Warn,
            );
        }

        $tmpDir = sys_get_temp_dir() . '/catraca-' . uniqid('', true);
        if (!mkdir($tmpDir, 0755, true) && !is_dir($tmpDir)) {
            throw new RuntimeException(sprintf('Directory "%s" was not created', $tmpDir));
        }

        $jsonPath = $tmpDir . '/phpmetrics.json';

        $process = new Process([
            $resolver->resolvePhp(),
            '-d',
            'memory_limit=1G',
            $phpmetrics,
            '--report-json=' . $jsonPath,
            ...(new SourcePathResolver())->resolveForBaseline($baseline),
        ], timeout: $baseline->getGateTimeout('complexity'));
        $process->run();

        $data = null;
        $rawReport = null;
        if (file_exists($jsonPath)) {
            $content = file_get_contents($jsonPath);
            if (is_string($content)) {
                $rawReport = $content;
                /** @var mixed $decoded */
                $decoded = json_decode($content, true);
                $data = is_array($decoded) ? $decoded : null;
            }
        }

        $this->cleanup($tmpDir);

        $exitCode = $process->getExitCode();
        if ($exitCode !== 0) {
            return $this->errorResult(
                $baseline,
                sprintf('PHP Metrics failed with exit code %s.', $exitCode ?? 'unknown'),
                $process->getErrorOutput(),
                $process->getOutput(),
            );
        }

        if ($data === null) {
            return $this->errorResult(
                $baseline,
                'PHP Metrics returned a missing or malformed JSON report.',
                $process->getErrorOutput(),
                $rawReport ?? $process->getOutput(),
            );
        }

        /** @var array<string, mixed> $report */
        $report = $data;

        return $this->parseResult($report, $baseline);
    }

    /**
     * @param  array<string, mixed>|null  $data
     */
    private function parseResult(?array $data, Baseline $baseline): GateResult
    {
        /** @var array<int, array{file: string, method: string, ccn: int}> $violations */
        $violations = [];
        /** @var array<int, array{file: string, method: string, ccn: int}> $warnings */
        $warnings = [];
        $maxCcn = 0;

        $blockAt = $baseline->getIntConfig('complexity', 'block_at', self::BLOCK_AT);
        $warnAt = $baseline->getIntConfig('complexity', 'warn_at', self::WARN_AT);

        $metricEntries = 0;
        foreach ($data as $key => $classData) {
            if (!is_string($key) || !is_array($classData) || !is_numeric($classData['ccnMethodMax'] ?? null)) {
                continue;
            }

            $metricEntries++;
            $ccn = (int) $classData['ccnMethodMax'];
            $entry = ['file' => $key, 'method' => 'ccnMethodMax', 'ccn' => $ccn];
            $maxCcn = max($maxCcn, $ccn);
            if ($ccn >= $blockAt) {
                $violations[] = $entry;
            } elseif ($ccn >= $warnAt) {
                $warnings[] = $entry;
            }
        }

        if ($data !== [] && $metricEntries === 0) {
            return $this->errorResult(
                $baseline,
                'PHP Metrics returned a JSON report without class complexity metrics.',
                '',
                (string) json_encode($data),
            );
        }

        $baselineMaxCcn = $baseline->getIntResult('complexity', 'max_ccn', 0);

        $status = Status::Pass;
        $actions = null;

        if (count($violations) > 0) {
            $status = Status::Fail;
            $actions = [[
                'type' => ActionType::Modularize,
                'message' => sprintf('%d methods exceed CCN %d (block threshold)', count($violations), $blockAt),
                'files' => array_map(
                    static fn(array $v): string => $v['file'] . ':' . $v['method'] . ' (CCN ' . $v['ccn'] . ')',
                    $violations,
                ),
            ]];
        }

        $warnFiles = array_map(
            static fn(array $w): string => $w['file'] . ':' . $w['method'] . ' (CCN ' . $w['ccn'] . ')',
            $warnings,
        );

        return new GateResult(
            status: $status,
            name: 'complexity',
            label: 'Cyclomatic Complexity',
            message: sprintf(
                'max CCN %d, %d violations (>=%d), %d warnings (>=%d) via phpmetrics',
                $maxCcn,
                count($violations),
                $blockAt,
                count($warnings),
                $warnAt,
            ),
            severity: Severity::Block,
            baseline: ['max_ccn' => $baselineMaxCcn],
            current: ['max_ccn' => $maxCcn, 'violations' => count($violations), 'warnings' => count($warnings)],
            actions: $actions,
            details: [
                'violations' => $violations,
                'warnings' => array_slice($warnings, 0, 20),
                'warning_files' => array_slice($warnFiles, 0, 20),
            ],
        );
    }

    private function errorResult(Baseline $baseline, string $message, string $errorOutput, string $output): GateResult
    {
        return new GateResult(
            status: Status::Fail,
            name: 'complexity',
            label: 'Cyclomatic Complexity',
            message: $message,
            severity: Severity::Block,
            baseline: ['max_ccn' => $baseline->getIntResult('complexity', 'max_ccn', 0)],
            current: null,
            details: [
                'stderr' => $errorOutput,
                'stdout' => $output,
            ],
        );
    }

    private function cleanup(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $files = glob($dir . '/*');
        if ($files !== false) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
        @rmdir($dir);
    }
}
