<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\PerformanceGate;
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
            echo json_encode([
                'files' => [[
                    'name' => 'src/Sample.php',
                    'appliedFixers' => ['no_unused_imports'],
                ]],
            ]);
            exit(8);
            PHP);
        chmod($this->tmpDir . '/vendor/bin/php-cs-fixer', 0755);
    }

    protected function tearDown(): void
    {
        foreach (
            ['catraca_baseline.json', 'performance-mode', 'vendor/bin/php-cs-fixer', 'src/Sample.php', '.catraca-cache/performance-php-cs-fixer.cache']
            as $path
        ) {
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
        $baseline = $this->baseline(
            ['no_unused_imports'],
            ['no_unused_imports' => true, 'autoload_optimization' => false, 'condition_order' => false],
        );

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(['violations' => 0], $result->current);
        self::assertSame(['no_unused_imports' => 1], $result->details['rules']['counts']);
        self::assertFileExists($this->tmpDir . '/.catraca-cache/performance-php-cs-fixer.cache');
    }

    public function test_non_informational_fixer_findings_block(): void
    {
        $baseline = $this->baseline(
            [],
            ['no_unused_imports' => true, 'autoload_optimization' => false, 'condition_order' => false],
        );

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['violations' => 1], $result->current);
    }

    public function test_malformed_fixer_report_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/performance-mode', 'malformed');
        $baseline = $this->baseline(
            [],
            ['no_unused_imports' => true, 'autoload_optimization' => false, 'condition_order' => false],
        );

        $result = (new PerformanceGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['violations' => 1], $result->current);
        self::assertContains(
            'PHP CS Fixer returned an invalid JSON report',
            $result->actions[0]['files'] ?? [],
        );
    }

    /** @param array<int, string> $informationalRules @param array<string, bool> $rules */
    private function baseline(array $informationalRules, array $rules): Baseline
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'source_dirs' => ['paths' => ['src']],
                'tools' => ['lint' => 'php-cs-fixer'],
                'performance' => [
                    'rules' => $rules,
                    'informational_rules' => $informationalRules,
                ],
            ],
            'results' => ['performance' => ['violations' => 0]],
        ]);

        return $baseline;
    }
}
