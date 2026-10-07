<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Baseline;
use B7S\Catraca\Catraca;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

use function file_exists;
use function file_get_contents;
use function json_decode;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

use const JSON_THROW_ON_ERROR;

final class CatracaTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-cli-test-' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tmpDir . '/catraca_baseline.json')) {
            unlink($this->tmpDir . '/catraca_baseline.json');
        }
        rmdir($this->tmpDir);
    }

    public function test_gate_selection_rejects_empty_and_unknown_names(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Catraca::parseGateSelection('style,');
    }

    public function test_gate_selection_runs_only_requested_gates_and_records_metadata(): void
    {
        $catraca = new Catraca($this->tmpDir, selectedGates: Catraca::parseGateSelection('style'), sequential: true);

        self::assertSame(['Code Style'], $catraca->getGateLabels());
        $result = $catraca->check()->toArray();

        self::assertCount(1, $result['gates']);
        self::assertArrayHasKey('elapsed_ms', $result['gates'][0]);
        self::assertArrayHasKey('executed_tools', $result['gates'][0]);
    }

    public function test_native_check_round_trip_preserves_configured_lists(): void
    {
        $baseline = new Baseline($this->tmpDir);
        $baseline->write([
            'config' => [
                'source_dirs' => [
                    'paths' => ['custom-src', 'secondary-src'],
                    'exclude' => [],
                ],
                'performance' => [
                    'informational_rules' => ['global_namespace_import', 'native_function_invocation'],
                ],
            ],
            'results' => [],
        ]);

        (new Catraca($this->tmpDir, selectedGates: ['file_size'], sequential: true))->check();

        /** @var array<string, mixed> $data */
        $data = json_decode((string) file_get_contents($baseline->getPath()), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame(['custom-src', 'secondary-src'], $data['config']['source_dirs']['paths']);
        self::assertSame([], $data['config']['source_dirs']['exclude']);
        self::assertSame(
            ['global_namespace_import', 'native_function_invocation'],
            $data['config']['performance']['informational_rules'],
        );
    }
}
