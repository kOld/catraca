<?php

declare(strict_types=1);

namespace B7S\Catraca;

use B7S\Catraca\Gate\ComplexityGate;
use B7S\Catraca\Gate\CoverageGate;
use B7S\Catraca\Gate\DuplicationGate;
use B7S\Catraca\Gate\FileSizeGate;
use B7S\Catraca\Gate\PerformanceGate;
use B7S\Catraca\Gate\SecurityGate;
use B7S\Catraca\Gate\StaticAnalysisGate;
use B7S\Catraca\Gate\StyleGate;
use InvalidArgumentException;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use function explode;
use function implode;
use function in_array;
use function trim;

class Catraca
{
    private Baseline $baseline;

    private GateRunner $gateRunner;

    public function __construct(
        string $projectRoot,
        string $profile = 'default',
        ?string $changedFrom = null,
        ?int $timeoutOverride = null,
        ?array $selectedGates = null,
        bool $sequential = false,
    ) {
        $this->baseline = new Baseline(
            $projectRoot,
            profile: $profile,
            changedFrom: $changedFrom,
            timeoutOverride: $timeoutOverride,
        );
        $resolver = new ToolResolver($projectRoot);

        $gates = [
            'security' => ['gate' => new SecurityGate(), 'name' => 'Security Audit'],
            'style' => ['gate' => new StyleGate(), 'name' => 'Code Style'],
            'static_analysis' => ['gate' => new StaticAnalysisGate(), 'name' => 'Static Analysis'],
            'coverage' => ['gate' => new CoverageGate(), 'name' => 'Test Coverage'],
            'duplication' => ['gate' => new DuplicationGate(), 'name' => 'Duplication'],
            'file_size' => ['gate' => new FileSizeGate(), 'name' => 'File Size'],
            'complexity' => ['gate' => new ComplexityGate(), 'name' => 'Cyclomatic Complexity'],
            'performance' => ['gate' => new PerformanceGate(), 'name' => 'Performance'],
        ];

        if ($selectedGates !== null) {
            $gates = array_filter(
                $gates,
                static fn(string $name): bool => in_array($name, $selectedGates, true),
                ARRAY_FILTER_USE_KEY,
            );
        }

        $this->gateRunner = new GateRunner($this->baseline, $resolver, array_values($gates), !$sequential);
    }

    /** @return array<int, string> */
    public static function gateNames(): array
    {
        return [
            'security',
            'style',
            'static_analysis',
            'coverage',
            'duplication',
            'file_size',
            'complexity',
            'performance',
        ];
    }

    /**
     * @return array<int, string>|null
     */
    public static function parseGateSelection(?string $selection): ?array
    {
        if ($selection === null) {
            return null;
        }

        $gates = array_map(static fn(string $gate): string => trim($gate), explode(',', $selection));
        $validGates = self::gateNames();

        if (in_array('', $gates, true) || count($gates) !== count(array_unique($gates))) {
            throw new InvalidArgumentException('The --gates option must contain each gate name once.');
        }

        foreach ($gates as $gate) {
            if (!in_array($gate, $validGates, true)) {
                throw new InvalidArgumentException(sprintf(
                    'Unknown gate "%s". Use one of: %s.',
                    $gate,
                    implode(', ', $validGates),
                ));
            }
        }

        return $gates;
    }

    /**
     * @return array<int, string>
     */
    public function getGateLabels(): array
    {
        return $this->gateRunner->getLabels();
    }

    public function cancel(): void
    {
        $this->gateRunner->cancel();
    }

    public function init(?GateRunObserverInterface $observer = null): CheckResult
    {
        $start = hrtime(true);
        $result = new CheckResult();

        $this->baseline->init();
        $this->runGates($result, $observer);
        $this->writeBaseline($result);

        $result->setMetrics((int) (hrtime(true) - $start), memory_get_peak_usage(true));

        return $result;
    }

    public function check(?GateRunObserverInterface $observer = null): CheckResult
    {
        $this->baseline->init();

        $start = hrtime(true);
        $result = new CheckResult();
        $this->runGates($result, $observer);

        $result->setMetrics((int) (hrtime(true) - $start), memory_get_peak_usage(true));

        return $result;
    }

    private function writeBaseline(CheckResult $result): void
    {
        $results = [];

        foreach ($result->getGates() as $gate) {
            if ($gate->current !== null) {
                $results[$gate->name] = $gate->current;
            }
        }

        $this->baseline->updateResults($results);
    }

    private function runGates(CheckResult $result, ?GateRunObserverInterface $observer): void
    {
        foreach ($this->gateRunner->run($observer) as $gateResult) {
            $result->add($gateResult);
        }
    }
}
