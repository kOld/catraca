<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\StyleGate;
use B7S\Catraca\GatePolicyEvaluator;
use B7S\Catraca\ToolResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function chmod;
use function file_exists;
use function file_put_contents;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class StyleGateTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-style-test-' . uniqid('', true);
        mkdir($this->tmpDir . '/vendor/bin', 0755, true);
        mkdir($this->tmpDir . '/src', 0755, true);
        file_put_contents($this->tmpDir . '/src/Sample.php', "<?php\n");
        file_put_contents($this->tmpDir . '/vendor/bin/pint', <<<'PHP'
            #!/usr/bin/env php
            <?php
            fwrite(STDERR, 'pint crashed');
            exit(2);
            PHP);
        file_put_contents($this->tmpDir . '/vendor/bin/php-cs-fixer', <<<'PHP'
            #!/usr/bin/env php
            <?php
            fwrite(STDERR, 'php-cs-fixer crashed');
            exit(16);
            PHP);
        chmod($this->tmpDir . '/vendor/bin/pint', 0755);
        chmod($this->tmpDir . '/vendor/bin/php-cs-fixer', 0755);
    }

    protected function tearDown(): void
    {
        foreach (['catraca_baseline.json', 'src/Sample.php', 'vendor/bin/pint', 'vendor/bin/php-cs-fixer'] as $path) {
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

    #[DataProvider('executionFailureCases')]
    public function test_execution_failure_cannot_be_downgraded_by_policy(string $tool, string $mode): void
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'source_dirs' => ['paths' => ['src']],
                'tools' => ['format' => $tool],
                'style' => ['mode' => $mode],
            ],
            'results' => ['style' => ['violations' => 10]],
        ]);

        $result = (new GatePolicyEvaluator())->evaluate(
            (new StyleGate())->run($baseline, new ToolResolver($this->tmpDir)),
            $baseline,
        );

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
    }

    /** @return array<string, array{tool: string, mode: string}> */
    public static function executionFailureCases(): array
    {
        return [
            'pint no regression' => ['tool' => 'pint', 'mode' => 'no_regression'],
            'pint informational' => ['tool' => 'pint', 'mode' => 'informational'],
            'php cs fixer no regression' => ['tool' => 'php-cs-fixer', 'mode' => 'no_regression'],
            'php cs fixer informational' => ['tool' => 'php-cs-fixer', 'mode' => 'informational'],
        ];
    }
}
