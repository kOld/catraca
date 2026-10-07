<?php

declare(strict_types=1);

namespace B7S\Catraca;

use B7S\Catraca\Enum\Status;
use B7S\Catraca\Gate\ComplexityGate;
use B7S\Catraca\Gate\CoverageGate;
use B7S\Catraca\Gate\DuplicationGate;
use B7S\Catraca\Gate\FileSizeGate;
use B7S\Catraca\Gate\PerformanceGate;
use B7S\Catraca\Gate\SecurityGate;
use B7S\Catraca\Gate\StaticAnalysisGate;
use B7S\Catraca\Gate\StyleGate;
use Parallite\ForkExecutor;
use Throwable;

use function array_keys;
use function array_map;
use function count;
use function get_class;
use function hrtime;
use function is_array;
use function min;
use function preg_match;
use function strtolower;
use function trim;

class GateRunner
{
    private ?ParallelTaskRunner $activeRunner = null;

    private bool $cancelled = false;

    /**
     * @param  array<int, array{gate: GateInterface, name: string}>  $gates
     */
    public function __construct(
        private Baseline $baseline,
        private ToolResolver $resolver,
        private array $gates,
        private bool $parallel = true,
    ) {}

    /**
     * @return array<int, string>
     */
    public function getLabels(): array
    {
        return array_map(static fn(array $gate): string => $gate['name'], $this->gates);
    }

    /**
     * @return array<int, GateResult>
     */
    public function run(?GateRunObserverInterface $observer = null): array
    {
        if ($this->parallel && $this->baseline->isParallelEnabled() && ForkExecutor::isAvailable()) {
            return $this->runParallel($observer);
        }

        return $this->runSequential($observer);
    }

    /**
     * @return array<int, GateResult>
     */
    private function runSequential(?GateRunObserverInterface $observer): array
    {
        $results = [];

        foreach ($this->gates as $index => $gateDef) {
            $observer?->started($index);
            if ($this->cancelled) {
                $gateResult = $this->cancelledResult($gateDef['name']);
                $results[] = $gateResult;
                $observer?->finished($index, $gateResult);

                continue;
            }

            $observer?->tick();

            $startedAt = hrtime(true);
            try {
                $gateResult = $gateDef['gate']->run($this->baseline, $this->resolver);
            } catch (Throwable $exception) {
                $gateResult = $this->errorResult($gateDef['name'], $exception);
            }
            $gateResult = $this->decorateResult(
                $gateResult,
                (int) (hrtime(true) - $startedAt),
                $gateDef['gate'],
            );
            $gateResult = (new GatePolicyEvaluator())->evaluate($gateResult, $this->baseline);

            $results[] = $gateResult;
            $observer?->finished($index, $gateResult);
        }

        return $results;
    }

    /**
     * Uses a bounded rolling worker pool. Completed gates are reported
     * immediately and the next queued gate starts as soon as a slot is free.
     *
     * @return array<int, GateResult>
     */
    private function runParallel(?GateRunObserverInterface $observer): array
    {
        $projectRoot = $this->baseline->projectRoot;
        $closures = [];

        $profile = $this->baseline->getProfile();
        $changedFrom = $this->baseline->getChangedFrom();
        foreach ($this->gates as $gateDef) {
            $gateName = $gateDef['name'];
            $gateClass = $gateDef['gate']::class;

            $closures[] = static function () use ($projectRoot, $gateName, $gateClass, $profile, $changedFrom): array {
                try {
                    // The gate is already a worker, so child gates must not
                    // recursively create another worker pool.
                    $baseline = new Baseline(
                        $projectRoot,
                        parallelOverride: false,
                        profile: $profile,
                        changedFrom: $changedFrom,
                    );
                    $resolver = new ToolResolver($projectRoot);
                    $gate = new $gateClass();

                    $startedAt = hrtime(true);
                    $result = $gate->run($baseline, $resolver);

                    return $result
                        ->withExecutionMetadata(
                            (int) (hrtime(true) - $startedAt),
                            self::executedTools($gate, $result),
                        )
                        ->toArray();
                } catch (Throwable $exception) {
                    return self::errorData($gateName, $exception);
                }
            };
        }

        if ($closures === []) {
            return [];
        }

        $this->activeRunner = new ParallelTaskRunner(min($this->baseline->getMaxProcesses(), count($closures)));

        $rawResults = $this->activeRunner->run(
            $closures,
            $observer === null ? null : static fn(int $index) => $observer->started($index),
            $observer === null ? null : static fn() => $observer->tick(),
            $observer === null
                ? null
                : function (int $index, mixed $data) use ($observer): void {
                    $observer->finished($index, $this->hydrateResult($index, $data));
                },
        );
        $this->activeRunner = null;

        return array_map(
            fn(mixed $data, int $index): GateResult => $this->hydrateResult($index, $data),
            $rawResults,
            array_keys($rawResults),
        );
    }

    private function hydrateResult(int $index, mixed $data): GateResult
    {
        $gateDef = $this->gates[$index];

        if ($data instanceof CancelledException) {
            return $this->cancelledResult($gateDef['name']);
        }
        if ($data instanceof Throwable) {
            return $this->errorResult($gateDef['name'], $data);
        }

        if (!is_array($data) || !GateResult::isSerializedData($data)) {
            return new GateResult(
                status: Status::Fail,
                name: 'unknown',
                label: $gateDef['name'],
                message: 'Invalid result from child process',
            );
        }

        /**
         * @var array{
         *     status: string,
         *     name: string,
         *     label: string,
         *     message: string,
         *     severity: string,
         *     baseline?: array<string, mixed>|null,
         *     current?: array<string, mixed>|null,
         *     actions?: array<int, array{type: string, message: string, files?: array<int, string>, reasons?: array<int, string>}>|null,
         *     details?: array<string, mixed>|null,
         *     elapsed_ns?: int|null,
         *     executed_tools?: array<int, string>
         * } $data
         */
        return (new GatePolicyEvaluator())->evaluate(GateResult::fromArray($data), $this->baseline);
    }

    private function decorateResult(GateResult $result, int $elapsedNanoseconds, GateInterface $gate): GateResult
    {
        return $result->withExecutionMetadata($elapsedNanoseconds, self::executedTools($gate, $result));
    }

    /**
     * Gate implementations intentionally return quality data only. The runner
     * adds the execution provenance so JSON consumers can see which work ran.
     *
     * @return array<int, string>
     */
    private static function executedTools(GateInterface $gate, GateResult $result): array
    {
        if ($result->status === Status::Skip) {
            return [];
        }

        if (preg_match('/\s+via\s+([^,)]+)/i', $result->message, $matches) === 1) {
            return [strtolower(trim($matches[1]))];
        }

        $tools = $result->details['tools'] ?? null;
        if (is_array($tools)) {
            $toolNames = [];
            foreach ($tools as $tool) {
                if (is_string($tool) && $tool !== '') {
                    $toolNames[] = $tool;
                }
            }
            if ($toolNames !== []) {
                return $toolNames;
            }
        }

        return match ($gate::class) {
            SecurityGate::class => ['composer audit', 'built-in security checks'],
            ComplexityGate::class => ['phpmetrics'],
            CoverageGate::class => ['test runner'],
            DuplicationGate::class => ['phpcpd'],
            FileSizeGate::class => ['built-in file-size scanner'],
            PerformanceGate::class => ['built-in performance checks'],
            StyleGate::class => ['code style tool'],
            StaticAnalysisGate::class => ['static analysis tool'],
            default => [],
        };
    }

    private function errorResult(string $label, Throwable $exception): GateResult
    {
        return new GateResult(
            status: Status::Fail,
            name: 'unknown',
            label: $label,
            message: 'Error: ' . $exception->getMessage(),
            details: [
                'exception' => get_class($exception),
                'trace' => $exception->getTraceAsString(),
            ],
        );
    }

    public function cancel(): void
    {
        $this->cancelled = true;
        $this->activeRunner?->cancel();
    }

    private function cancelledResult(string $label): GateResult
    {
        return new GateResult(
            status: Status::Cancelled,
            name: 'cancelled',
            label: $label,
            message: 'Cancelled by signal',
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function errorData(string $label, Throwable $exception): array
    {
        return [
            'status' => 'fail',
            'name' => 'unknown',
            'label' => $label,
            'message' => 'Error: ' . $exception->getMessage(),
            'severity' => 'block',
            'details' => [
                'exception' => get_class($exception),
                'trace' => $exception->getTraceAsString(),
            ],
        ];
    }
}
