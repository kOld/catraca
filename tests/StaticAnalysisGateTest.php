<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\StaticAnalysisGate;
use B7S\Catraca\ToolResolver;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function chmod;
use function file_get_contents;
use function file_put_contents;
use function is_file;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class StaticAnalysisGateTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-static-analysis-test-' . uniqid('', true);
        mkdir($this->tmpDir . '/vendor/bin', 0755, true);
        file_put_contents($this->tmpDir . '/phpstan.neon', "parameters:\n    level: 5\n");
        file_put_contents($this->tmpDir . '/phpstan-mode', 'pass');
        file_put_contents($this->tmpDir . '/vendor/bin/phpstan', <<<'PHP'
            #!/usr/bin/env php

            <?php

            $root = dirname(__DIR__, 2);
            file_put_contents($root . '/phpstan-calls.log', implode(' ', array_slice($argv, 1)) . PHP_EOL, FILE_APPEND);
            $mode = trim((string) file_get_contents($root . '/phpstan-mode'));

            if ($mode === 'invalid') {
                fwrite(STDERR, 'not-json');
                exit(255);
            }

            if ($mode === 'errors') {
                echo json_encode([
                    'totals' => ['errors' => 2, 'file_errors' => 0],
                    'files' => [],
                ]);
                exit(1);
            }

            if ($mode === 'global-errors') {
                echo json_encode([
                    'totals' => ['errors' => 0, 'file_errors' => 0],
                    'files' => [],
                    'errors' => ['PHPStan worker crashed while loading the project'],
                ]);
                exit(1);
            }
            if ($mode === 'malformed-totals') {
                echo json_encode(['totals' => [], 'files' => []]);
                exit(0);
            }
            if ($mode === 'counted-global-errors') {
                echo json_encode([
                    'totals' => ['errors' => 1, 'file_errors' => 0],
                    'files' => [],
                    'errors' => ['A global error already included in totals'],
                ]);
                exit(1);
            }

            echo json_encode([
                'totals' => ['errors' => 0, 'file_errors' => 0],
                'files' => [],
            ]);
            PHP);
        chmod($this->tmpDir . '/vendor/bin/phpstan', 0755);
    }

    protected function tearDown(): void
    {
        foreach ([
            '/catraca_baseline.json',
            '/phpstan.neon',
            '/phpstan-mode',
            '/phpstan-calls.log',
            '/vendor/bin/phpstan',
        ] as $path) {
            $absolutePath = $this->tmpDir . $path;
            if (is_file($absolutePath)) {
                unlink($absolutePath);
            }
        }

        rmdir($this->tmpDir . '/vendor/bin');
        rmdir($this->tmpDir . '/vendor');
        rmdir($this->tmpDir);
    }

    public function test_phpstan_memory_limit_is_configurable(): void
    {
        $baseline = $this->createBaseline('4G');
        $result = (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Pass, $result->status);
        self::assertStringContainsString('--memory-limit=4G', (string) file_get_contents($this->tmpDir . '/phpstan-calls.log'));
    }

    public function test_phpstan_error_exit_code_is_parsed_as_a_quality_failure(): void
    {
        file_put_contents($this->tmpDir . '/phpstan-mode', 'errors');
        $baseline = $this->createBaseline('4G');
        $result = (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['errors' => 2], $result->current);
    }

    public function test_phpstan_global_errors_are_preserved_as_quality_failures(): void
    {
        file_put_contents($this->tmpDir . '/phpstan-mode', 'global-errors');
        $baseline = $this->createBaseline('4G');

        $result = (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['errors' => 1], $result->current);
        self::assertSame(
            'PHPStan worker crashed while loading the project',
            $result->details['errors'][0]['message'],
        );
        self::assertSame(
            'PHPStan worker crashed while loading the project',
            $result->details['errors'][0]['raw'],
        );
        self::assertSame('[global]', $result->details['errors'][0]['file']);
    }

    public function test_invalid_phpstan_output_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/phpstan-mode', 'invalid');
        $baseline = $this->createBaseline('4G');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('invalid JSON');

        (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));
    }

    public function test_missing_phpstan_totals_cannot_be_reported_as_zero_errors(): void
    {
        file_put_contents($this->tmpDir . '/phpstan-mode', 'malformed-totals');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('invalid result');

        (new StaticAnalysisGate())->run($this->createBaseline('4G'), new ToolResolver($this->tmpDir));
    }

    public function test_phpstan_global_errors_are_not_counted_twice(): void
    {
        file_put_contents($this->tmpDir . '/phpstan-mode', 'counted-global-errors');

        $result = (new StaticAnalysisGate())->run($this->createBaseline('4G'), new ToolResolver($this->tmpDir));

        self::assertSame(['errors' => 1], $result->current);
        self::assertSame('A global error already included in totals', $result->details['errors'][0]['message']);
    }

    public function test_invalid_phpstan_memory_limit_is_rejected(): void
    {
        $baseline = $this->createBaseline('unlimited-ish');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid PHPStan memory limit');

        (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));
    }

    public function test_non_string_phpstan_memory_limit_is_rejected(): void
    {
        $baseline = $this->createBaseline(4096);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid PHPStan memory limit');

        (new StaticAnalysisGate())->run($baseline, new ToolResolver($this->tmpDir));
    }

    private function createBaseline(mixed $memoryLimit): Baseline
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'tools' => [
                    'options' => [
                        'phpstan' => ['memory_limit' => $memoryLimit],
                    ],
                ],
            ],
            'results' => ['static_analysis' => ['errors' => 0]],
        ]);

        return $baseline;
    }
}
