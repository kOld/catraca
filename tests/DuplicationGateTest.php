<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\DuplicationGate;
use B7S\Catraca\GateResult;
use B7S\Catraca\ToolResolver;
use PHPUnit\Framework\TestCase;

use function chmod;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class DuplicationGateTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-duplication-test-' . uniqid('', true);
        mkdir($this->tmpDir . '/vendor/bin', 0755, true);
        mkdir($this->tmpDir . '/src', 0755, true);
        file_put_contents($this->tmpDir . '/src/Sample.php', "<?php\n");
        foreach (['First.php', 'Second.php', 'Third.php', 'Fourth.php'] as $file) {
            file_put_contents(
                $this->tmpDir . '/src/' . $file,
                "<?php\nfunction duplicated(): array\n{\n    return ['one', 'two'];\n}\n",
            );
        }
        file_put_contents($this->tmpDir . '/duplication-mode', 'clean');
        file_put_contents($this->tmpDir . '/vendor/bin/phpcpd', <<<'PHP'
            #!/usr/bin/env php
            <?php
            $root = dirname(__DIR__, 2);
            file_put_contents($root . '/duplication-memory.log', (string) ini_get('memory_limit'));
            if (trim((string) file_get_contents($root . '/duplication-mode')) === 'fail') {
                fwrite(STDERR, 'phpcpd failed');
                exit(7);
            }
            if (trim((string) file_get_contents($root . '/duplication-mode')) === 'malformed') {
                echo 'The report format changed';
                exit(0);
            }
            if (trim((string) file_get_contents($root . '/duplication-mode')) === 'clones') {
                echo "Found 3 code clones with 12 duplicated lines in 4 files:\n\n";
                echo "  - {$root}/src/First.php:1-4 (4 lines)\n";
                echo "    {$root}/src/Second.php:10-13\n\n";
                echo "  - {$root}/src/Third.php:20-23 (4 lines)\n";
                echo "    {$root}/src/Fourth.php:30-33\n\n";
                echo "12.34% duplicated lines out of 100 total lines of code.\n";
                exit(1);
            }
            echo "No code clones found.\n";
            PHP);
        chmod($this->tmpDir . '/vendor/bin/phpcpd', 0755);
    }

    protected function tearDown(): void
    {
        foreach ([
            'catraca_baseline.json',
            'duplication-mode',
            'duplication-memory.log',
            'vendor/bin/phpcpd',
            'src/Sample.php',
            'src/First.php',
            'src/Second.php',
            'src/Third.php',
            'src/Fourth.php',
        ] as $path) {
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

    public function test_clean_report_passes_and_child_receives_an_isolated_memory_limit(): void
    {
        $result = $this->runGate();

        self::assertSame(Status::Pass, $result->status);
        self::assertSame(['percentage' => 0.0, 'clones' => 0], $result->current);
        self::assertSame('1G', file_get_contents($this->tmpDir . '/duplication-memory.log'));
    }

    public function test_nonzero_process_without_a_duplication_report_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/duplication-mode', 'fail');

        $result = $this->runGate();

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame('phpcpd failed', $result->details['stderr']);
    }

    public function test_successful_process_with_malformed_output_fails_closed(): void
    {
        file_put_contents($this->tmpDir . '/duplication-mode', 'malformed');

        $result = $this->runGate();

        self::assertSame(Status::Fail, $result->status);
        self::assertNull($result->current);
        self::assertSame('The report format changed', $result->details['stdout']);
    }

    public function test_summary_clone_count_is_used_while_pair_samples_remain_details(): void
    {
        file_put_contents($this->tmpDir . '/duplication-mode', 'clones');

        $result = $this->runGate();

        self::assertSame(Status::Fail, $result->status);
        self::assertSame(['percentage' => 12.34, 'clones' => 3], $result->current);
        self::assertCount(2, $result->details['clones']);
        self::assertStringEndsWith('src/First.php:1-4', $result->details['clones'][0]['file_a']);
        self::assertStringEndsWith('src/Second.php:10-13', $result->details['clones'][0]['file_b']);
    }

    private function runGate(): GateResult
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => ['source_dirs' => ['paths' => ['src']]],
            'results' => ['duplication' => ['percentage' => 0.0, 'clones' => 0]],
        ]);

        return (new DuplicationGate())->run($baseline, new ToolResolver($this->tmpDir));
    }
}
