<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\PerformanceGate;
use B7S\Catraca\GatePolicyEvaluator;
use B7S\Catraca\ToolResolver;
use PHPUnit\Framework\TestCase;

use function chmod;
use function file_exists;
use function file_put_contents;
use function is_dir;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class PerformanceGateTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-performance-test-' . uniqid('', true);
        mkdir($this->tmpDir . '/vendor/bin', 0755, true);
        mkdir($this->tmpDir . '/src', 0755, true);
        file_put_contents($this->tmpDir . '/src/Sample.php', "<?php\n");
        file_put_contents($this->tmpDir . '/performance-mode', 'valid');
        file_put_contents($this->tmpDir . '/vendor/bin/php-cs-fixer', <<<'PHP'
            #!/usr/bin/env php
            <?php
            $root = dirname(__DIR__, 2);
            if (trim((string) file_get_contents($root . '/performance-mode')) === 'malformed') {
                echo '{broken';
                exit(0);
            }
            foreach ($argv as $argument) {
                if (str_starts_with($argument, '--cache-file=')) {
                    file_put_contents(substr($argument, strlen('--cache-file=')), 'cache');
                }
            }
            if (trim((string) file_get_contents($root . '/performance-mode')) === 'malformed-shape') {
                echo json_encode(['files' => [['garbage' => true]]]);
                exit(0);
            }
            if (trim((string) file_get_contents($root . '/performance-mode')) === 'clean') {
                echo json_encode(['files' => []]);
                exit(0);
            }
            echo json_encode([
                'files' => [[
                    'name' => 'src/Sample.php',
                    'appliedFixers' => ['no_unused_imports'],
                ]],
            ]);
            if (trim((string) file_get_contents($root . '/performance-mode')) === 'crash') {
                fwrite(STDERR, 'The fixer crashed after writing a partial report');
                exit(16);
            }
            exit(8);
            PHP);
        chmod($this->tmpDir . '/vendor/bin/php-cs-fixer', 0755);
    }

    protected function tearDown(): void
    {
        foreach ([
            'catraca_baseline.json',
            'performance-mode',
            'vendor/bin/php-cs-fixer',
            'src/Sample.php',
            '.catraca-cache/performance-php-cs-fixer.cache',
        ] as $path) {
            $absolutePath = $this->tmpDir . '/' . $path;
            if (file_exists($absolutePath)) {
                unlink($absolutePath);
            }
        }
        if (is_dir($this->tmpDir . '/.catraca-cache')) {
            rmdir($this->tmpDir . '/.catraca-cache');
        }
        rmdir($this->tmpDir . '/src');
        rmdir($this->tmpDir . '/vendor/bin');
        rmdir($this->tmpDir . '/vendor');
        rmdir($this->tmpDir);
    }

    public function test_informational_fixer_findings_are_reported_without_blocking(): void
    {
        $baseline = $this->baseline(['no_unused_imports'], [
            'no_unused_imports' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(['violations' => 0], $result->current);
        self::assertSame(['no_unused_imports' => 1], $result->details['rules']['counts']);
        self::assertFileExists($this->tmpDir . '/.catraca-cache/performance-php-cs-fixer.cache');
    }

    public function test_non_informational_fixer_findings_block(): void
    {
        $baseline = $this->baseline([], [
            'no_unused_imports' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['violations' => 1], $result->current);
    }

    public function test_malformed_fixer_report_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'malformed');
        $baseline = $this->baseline([], [
            'no_unused_imports' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame('{broken', $result->details['stdout']);
    }

    public function test_fixer_crash_cannot_be_masked_by_informational_rules(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'crash');
        $baseline = $this->baseline(['no_unused_imports'], [
            'no_unused_imports' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame(16, $result->details['exit_code']);
        self::assertSame('The fixer crashed after writing a partial report', $result->details['stderr']);
    }

    public function test_fixer_report_with_an_invalid_file_shape_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'malformed-shape');
        $baseline = $this->baseline(['no_unused_imports'], [
            'no_unused_imports' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame('{"files":[{"garbage":true}]}', $result->details['stdout']);
    }

    public function test_fixer_process_failure_remains_blocking_under_informational_policy(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'crash');
        $baseline = $this->baseline(
            ['no_unused_imports'],
            ['no_unused_imports' => true, 'autoload_optimization' => false, 'condition_order' => false],
            'informational',
        );

        $result = (new GatePolicyEvaluator())->evaluate(
            (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir)),
            $baseline,
        );

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
    }

    public function test_auto_chooses_php_cs_fixer_when_mago_cannot_cover_configured_rules(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'clean');
        $baseline = $this->baseline(
            [],
            ['no_unused_imports' => true, 'autoload_optimization' => false, 'condition_order' => false],
            'no_regression',
            'auto',
        );

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(['php-cs-fixer'], $result->details['tools']);
        self::assertSame([], $result->details['rules']['unexecuted']);
    }

    public function test_unknown_informational_rule_cannot_make_an_unanalyzed_rule_pass(): void
    {
        $baseline = $this->baseline(['typo_rule'], [
            'typo_rule' => true,
            'autoload_optimization' => false,
            'condition_order' => false,
        ]);

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame(['typo_rule'], $result->details['rules']['unexecuted']);
    }

    /** @param array<int, string> $informationalRules @param array<string, bool> $rules */
    private function baseline(
        array $informationalRules,
        array $rules,
        string $mode = 'no_regression',
        string $tool = 'php-cs-fixer',
    ): Baseline {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'source_dirs' => ['paths' => ['src']],
                'tools' => ['lint' => $tool],
                'performance' => [
                    'mode' => $mode,
                    'rules' => $rules,
                    'informational_rules' => $informationalRules,
                ],
            ],
            'results' => ['performance' => ['violations' => 0]],
        ]);

        return $baseline;
    }
}
