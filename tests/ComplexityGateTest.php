<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\ComplexityGate;
use B7S\Catraca\GateResult;
use B7S\Catraca\ToolResolver;
use PHPUnit\Framework\TestCase;

use function chmod;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function json_encode;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class ComplexityGateTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-complexity-test-' . uniqid('', true);
        mkdir($this->tmpDir . '/vendor/bin', 0755, true);
        mkdir($this->tmpDir . '/src', 0755, true);
        file_put_contents($this->tmpDir . '/src/Sample.php', "<?php\n");
        file_put_contents($this->tmpDir . '/metrics-mode', 'flat');
        file_put_contents($this->tmpDir . '/vendor/bin/phpmetrics', <<<'PHP'
            #!/usr/bin/env php
            <?php
            $root = dirname(__DIR__, 2);
            file_put_contents($root . '/metrics-memory.log', (string) ini_get('memory_limit'));
            $mode = trim((string) file_get_contents($root . '/metrics-mode'));
            $report = null;
            foreach ($argv as $argument) {
                if (str_starts_with($argument, '--report-json=')) {
                    $report = substr($argument, strlen('--report-json='));
                }
            }
            if ($mode === 'fail') {
                fwrite(STDERR, 'phpmetrics failed');
                exit(7);
            }
            if ($mode === 'malformed') {
                file_put_contents($report, '{broken');
                exit(0);
            }
            file_put_contents($report, json_encode($mode === 'empty'
                ? []
                : ['App\\Sample' => ['ccnMethodMax' => $mode === 'block' ? 40 : 21]],
            ));
            PHP);
        chmod($this->tmpDir . '/vendor/bin/phpmetrics', 0755);
    }

    protected function tearDown(): void
    {
        foreach (['catraca_baseline.json', 'metrics-mode', 'metrics-memory.log', 'vendor/bin/phpmetrics', 'src/Sample.php'] as $path) {
            $absolutePath = $this->tmpDir . '/' . $path;
            if (file_exists($absolutePath)) {
                unlink($absolutePath);
            }
        }
        rmdir($this->tmpDir . '/src');
        rmdir($this->tmpDir . '/vendor/bin');
        rmdir($this->tmpDir . '/vendor');
        rmdir($this->tmpDir);
    }

    public function test_parses_flat_phpmetrics_report_and_uses_ccn_method_max(): void
    {
        $result = $this->runGate();

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(['max_ccn' => 21, 'violations' => 0, 'warnings' => 1], $result->current);
        self::assertSame('1G', file_get_contents($this->tmpDir . '/metrics-memory.log'));
    }

    public function test_configured_block_threshold_is_applied_to_flat_report(): void
    {
        file_put_contents($this->tmpDir . '/metrics-mode', 'block');
        $baseline = $this->baseline(['block_at' => 40, 'warn_at' => 10]);

        $result = (new ComplexityGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(40, $result->current['max_ccn']);
    }

    public function test_malformed_report_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/metrics-mode', 'malformed');

        $result = $this->runGate();

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertStringContainsString('malformed', $result->message);
    }

    public function test_nonzero_report_process_fails_closed_and_preserves_stderr(): void
    {
        file_put_contents($this->tmpDir . '/metrics-mode', 'fail');

        $result = $this->runGate();

        self::assertSame(Status::Fail, $result->status);
        self::assertSame('phpmetrics failed', $result->details['stderr']);
    }

    public function test_valid_empty_report_is_a_zero_metric_result(): void
    {
        file_put_contents($this->tmpDir . '/metrics-mode', 'empty');

        $result = $this->runGate();

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(0, $result->current['max_ccn']);
    }

    /** @param array<string, int> $complexityConfig */
    private function baseline(array $complexityConfig = []): Baseline
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'source_dirs' => ['paths' => ['src']],
                'complexity' => ['block_at' => 50, 'warn_at' => 20, ...$complexityConfig],
            ],
            'results' => ['complexity' => ['max_ccn' => 0]],
        ]);

        return $baseline;
    }

    private function runGate(): GateResult
    {
        return (new ComplexityGate())->run($this->baseline(), new ToolResolver($this->tmpDir));
    }
}
