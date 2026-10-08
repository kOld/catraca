<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use B7S\Catraca\Analyzer\ConditionOrderAnalyzer;
use B7S\Catraca\Baseline;
use B7S\Catraca\CsFixerResultParser;
use B7S\Catraca\Enum\ActionType;
use B7S\Catraca\Enum\Severity;
use B7S\Catraca\Enum\Status;
use B7S\Catraca\GateInterface;
use B7S\Catraca\GateResult;
use B7S\Catraca\GateToolRegistry;
use B7S\Catraca\SourcePathResolver;
use B7S\Catraca\ToolResolver;
use Symfony\Component\Process\Process;

use function array_filter;
use function array_keys;
use function array_map;
use function array_merge;
use function array_slice;
use function array_unique;
use function array_values;
use function count;
use function dirname;
use function implode;
use function in_array;
use function is_array;
use function is_bool;
use function is_dir;
use function is_int;
use function is_string;
use function mkdir;
use function sprintf;
use function str_contains;
use function strtolower;
use function trim;

readonly class PerformanceGate implements GateInterface
{
    private const int MAX_VIOLATIONS = 0;

    public function __construct(
        private SourcePathResolver $pathResolver = new SourcePathResolver(),
    ) {}

    public function run(Baseline $baseline, ToolResolver $resolver): GateResult
    {
        $violations = 0;
        $files = [];
        $messages = [];
        $reasons = [];
        $hasTool = false;
        $analyzedRules = [];
        $unexecutedRules = [];
        $unsupportedRules = [];
        $ruleCounts = [];
        $informationalRules = $this->getInformationalRules($baseline);
        $executedTools = [];

        $enabledRules = $this->getEnabledRules($baseline);
        $tool = GateToolRegistry::resolve($baseline, $resolver, 'performance');
        $fixer = $tool !== null && $tool->name === 'php-cs-fixer' ? $tool->path : null;
        $paths = $this->pathResolver->resolveForBaseline($baseline);

        if ($fixer !== null) {
            $rulesJson = self::buildRulesJson($enabledRules);

            if ($rulesJson !== '{}') {
                $result = $this->runCsFixerRules(
                    $fixer,
                    $resolver,
                    $rulesJson,
                    $paths,
                    $baseline->getGateTimeout('performance'),
                    $baseline->getPhpCsFixerCacheFile(),
                );
                $hasTool = true;
                $violations = $result['violations'];
                $files = $result['files'];
                $ruleCounts = $result['rule_counts'];
                $analyzedRules = array_values(array_filter(
                    array_keys($this->getRuleRegistry()),
                    static fn(string $rule): bool => ($enabledRules[$rule] ?? false) === true,
                ));
                $unsupportedRules = $result['unsupported_rules'];
                $executedTools[] = 'php-cs-fixer';

                if (!$result['valid']) {
                    return new GateResult(
                        status: Status::Fail,
                        name: 'performance',
                        label: 'Performance',
                        message: 'PHP CS Fixer failed or returned an invalid report.',
                        severity: Severity::Block,
                        baseline: ['violations' => $baseline->getIntResult('performance', 'violations', 0)],
                        current: null,
                        details: [
                            'stdout' => $result['stdout'],
                            'stderr' => $result['stderr'],
                            'exit_code' => $result['exit_code'],
                            'tools' => $executedTools,
                        ],
                    );
                }

                if ($ruleCounts !== []) {
                    $informationalCount = 0;
                    $blockingCount = 0;
                    foreach ($ruleCounts as $rule => $ruleCount) {
                        if (in_array($rule, $informationalRules, true)) {
                            $informationalCount += $ruleCount;
                        } else {
                            $blockingCount += $ruleCount;
                        }
                    }
                    $violations = $blockingCount;
                    if ($informationalCount > 0) {
                        $messages[] = sprintf('%d informational performance improvement(s) found', $informationalCount);
                    }
                }

                if ($violations > self::MAX_VIOLATIONS) {
                    $messages[] = sprintf('%d files with performance improvements available', $violations);
                }
            }
        }

        if ($enabledRules['autoload_optimization'] ?? true) {
            $autoloadResult = $this->checkAutoloadOptimization($resolver);
            if ($autoloadResult !== null) {
                $hasTool = true;
                $executedTools[] = 'composer autoload optimization';
                $violations += $autoloadResult['violations'];
                $files = array_merge($files, $autoloadResult['files']);
                if ($autoloadResult['violations'] > self::MAX_VIOLATIONS) {
                    $messages[] = $autoloadResult['message'];
                }
                $analyzedRules[] = 'autoload_optimization';
            }
        }

        if ($enabledRules['condition_order'] ?? true) {
            $conditionResult = $this->checkConditionOrder($paths);
            $hasTool = true;
            $executedTools[] = 'condition-order scanner';
            $violations += $conditionResult['violations'];
            $files = array_merge($files, $conditionResult['files']);
            $reasons = array_merge($reasons, $conditionResult['reasons']);
            if ($conditionResult['violations'] > self::MAX_VIOLATIONS) {
                $messages[] = $conditionResult['message'];
            }
            $analyzedRules[] = 'condition_order';
        }

        foreach ($enabledRules as $rule => $enabled) {
            if ($enabled && !in_array($rule, $analyzedRules, true)) {
                $unexecutedRules[] = $rule;
            }
        }
        $unexecutedRules = array_values(array_unique(array_merge($unexecutedRules, $unsupportedRules)));
        $knownRules = array_merge(array_keys($this->getRuleRegistry()), ['autoload_optimization', 'condition_order']);
        $blockingUnexecutedRules = array_values(array_filter(
            $unexecutedRules,
            static fn(string $rule): bool => (
                !in_array($rule, $informationalRules, true)
                || in_array($rule, $unsupportedRules, true)
                || !in_array($rule, $knownRules, true)
            ),
        ));
        if ($unexecutedRules !== []) {
            $violations += count($blockingUnexecutedRules);
            $messages[] = sprintf('No executable analyzer for: %s', implode(', ', $unexecutedRules));
            $reasons = array_merge($reasons, array_map(
                static fn(string $rule): string => $rule . ' was not analyzed',
                $unexecutedRules,
            ));
        }

        if ($blockingUnexecutedRules !== []) {
            return new GateResult(
                status: Status::Fail,
                name: 'performance',
                label: 'Performance',
                message: sprintf('No executable analyzer for: %s', implode(', ', $blockingUnexecutedRules)),
                severity: Severity::Block,
                baseline: ['violations' => $baseline->getIntResult('performance', 'violations', 0)],
                current: null,
                details: [
                    'rules' => [
                        'configured' => array_keys(array_filter($enabledRules)),
                        'analyzed' => array_values(array_unique($analyzedRules)),
                        'unsupported' => $unsupportedRules,
                        'unexecuted' => $unexecutedRules,
                        'informational' => $informationalRules,
                        'counts' => $ruleCounts,
                    ],
                    'tools' => array_values(array_unique($executedTools)),
                ],
            );
        }

        if (!$hasTool) {
            return new GateResult(
                status: Status::Skip,
                name: 'performance',
                label: 'Performance',
                message: 'No performance tools found',
                severity: Severity::Warn,
            );
        }

        $baselineViolations = $baseline->getIntResult('performance', 'violations', self::MAX_VIOLATIONS);
        [$status, $actions] = $this->evaluateViolations($violations, $files, $messages, $reasons);

        $message = $violations > self::MAX_VIOLATIONS
            ? sprintf('%d improvement(s) found (baseline: %d)', $violations, $baselineViolations)
            : (
                $ruleCounts === []
                    ? 'No performance improvements needed'
                    : sprintf('%d informational performance findings; no blocking findings', array_sum($ruleCounts))
            );

        return new GateResult(
            status: $status,
            name: 'performance',
            label: 'Performance',
            message: $message,
            severity: Severity::Block,
            baseline: ['violations' => $baselineViolations],
            current: ['violations' => $violations],
            actions: $actions,
            details: [
                'rules' => [
                    'configured' => array_keys(array_filter($enabledRules)),
                    'analyzed' => array_values(array_unique($analyzedRules)),
                    'unsupported' => $unsupportedRules,
                    'unexecuted' => $unexecutedRules,
                    'informational' => $informationalRules,
                    'counts' => $ruleCounts,
                ],
                'tools' => array_values(array_unique($executedTools)),
            ],
        );
    }

    /**
     * @return array<string, array{rule: string, message: string}>
     */
    public static function getRuleRegistry(): array
    {
        return [
            'global_namespace_import' => [
                'rule' => '{"global_namespace_import":{"import_classes":true,"import_constants":true,"import_functions":true}}',
                'message' => '%d global imports missing (use class/function/const)',
            ],
            'no_unused_imports' => [
                'rule' => 'no_unused_imports',
                'message' => '%d files with unused imports',
            ],
            'fully_qualified_strict_types' => [
                'rule' => '{"fully_qualified_strict_types":{"import_symbols":true}}',
                'message' => '%d files with redundant FQCNs',
            ],
            'lambda_not_used_import' => [
                'rule' => 'lambda_not_used_import',
                'message' => '%d closures with unused "use" variables',
            ],
            'native_function_invocation' => [
                'rule' => '{"native_function_invocation":{"include":["@compiler_optimized"],"scope":"all","strict":true}}',
                'message' => '%d native function calls without backslash prefix',
            ],
            'no_redundant_readonly_property' => [
                'rule' => 'no_redundant_readonly_property',
                'message' => '%d redundant readonly property declarations',
            ],
            'static_lambda' => [
                'rule' => 'static_lambda',
                'message' => '%d lambdas that should be declared static',
            ],
            'array_push' => [
                'rule' => 'array_push',
                'message' => '%d array_push() calls — use $arr[] = instead',
            ],
            'ereg_to_preg' => [
                'rule' => 'ereg_to_preg',
                'message' => '%d deprecated ereg function calls',
            ],
            'modernize_strpos' => [
                'rule' => 'modernize_strpos',
                'message' => '%d strpos() calls — use str_contains/str_starts_with/str_ends_with',
            ],
            'pow_to_exponentiation' => [
                'rule' => 'pow_to_exponentiation',
                'message' => '%d pow() calls — use ** operator instead',
            ],
            'random_api_migration' => [
                'rule' => 'random_api_migration',
                'message' => '%d rand()/mt_rand() calls — use random_int() instead',
            ],
            'set_type_to_cast' => [
                'rule' => 'set_type_to_cast',
                'message' => '%d settype() calls — use type casting instead',
            ],
        ];
    }

    /**
     * @param  array<string, bool>  $enabledRules
     */
    public static function buildRulesJson(array $enabledRules): string
    {
        $registry = self::getRuleRegistry();
        $rules = [];
        foreach ($registry as $key => $config) {
            if (!($enabledRules[$key] ?? false)) {
                continue;
            }
            /** @var array<string, mixed>|string|bool|null $decoded */
            $decoded = json_decode($config['rule'], true);
            if (is_array($decoded)) {
                foreach ($decoded as $name => $cfg) {
                    $rules[$name] = $cfg;
                }
            } else {
                $rules[$config['rule']] = true;
            }
        }

        return $rules === [] ? '{}' : (json_encode($rules, JSON_UNESCAPED_SLASHES) ?: '{}');
    }

    /**
     * @return array<string, bool>
     */
    private function getEnabledRules(Baseline $baseline): array
    {
        /** @var array<string, mixed> $rules */
        $rules = $baseline->getArrayConfig('performance', 'rules', []);
        if ($rules !== []) {
            $enabled = [];
            foreach ($rules as $rule => $value) {
                if (is_bool($value)) {
                    $enabled[$rule] = $value;
                }
            }

            return $enabled;
        }

        $defaults = array_fill_keys(array_keys(self::getRuleRegistry()), true);
        $defaults['autoload_optimization'] = true;

        return $defaults;
    }

    /** @return array<int, string> */
    private function getInformationalRules(Baseline $baseline): array
    {
        /** @var array<string, mixed> $configured */
        $configured = $baseline->getArrayConfig('performance', 'informational_rules', []);
        $rules = [];
        foreach ($configured as $rule) {
            if (is_string($rule) && $rule !== '') {
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    /**
     * @param  array<int, string>  $paths
     * @return array{violations: int, files: array<int, string>, rule_counts: array<string, int>, unsupported_rules: array<int, string>, valid: bool, stdout: string, stderr: string, exit_code: int|null}
     */
    private function runCsFixerRules(
        string $fixer,
        ToolResolver $resolver,
        string $rulesJson,
        array $paths,
        ?float $timeout,
        string $cacheFile,
    ): array {
        $cacheDir = dirname($cacheFile);
        if (!is_dir($cacheDir) && !mkdir($cacheDir, 0755, true) && !is_dir($cacheDir)) {
            return [
                'violations' => 1,
                'files' => ['Unable to create PHP CS Fixer cache directory: ' . $cacheDir],
                'rule_counts' => [],
                'unsupported_rules' => [],
                'valid' => false,
                'stdout' => '',
                'stderr' => 'Unable to create PHP CS Fixer cache directory: ' . $cacheDir,
                'exit_code' => null,
            ];
        }

        $cmd = [
            $resolver->resolvePhp(),
            $fixer,
            'fix',
            '--dry-run',
            '--diff',
            '--allow-risky=yes',
            '--using-cache=yes',
            '--cache-file=' . $cacheFile,
            '--format=json',
            '--verbose',
            '--rules=' . $rulesJson,
        ];
        foreach ($paths as $path) {
            $cmd[] = $path;
        }

        /** @var array<int, string> $cmd */
        $process = new Process($cmd, timeout: $timeout);
        $process->run();

        $result = CsFixerResultParser::parseJsonOutput($process->getOutput());
        $result['stdout'] = $process->getOutput();
        $result['stderr'] = $process->getErrorOutput();
        $result['exit_code'] = $process->getExitCode();
        if (!in_array($process->getExitCode(), [0, 8], true)) {
            $result['valid'] = false;
        }
        if (!$result['valid']) {
            $result['violations'] = max(1, $result['violations']);
            $result['files'][] = 'PHP CS Fixer returned an invalid JSON report';
        }
        if ($result['violations'] === 0 && $process->getExitCode() !== 0) {
            $result['violations'] = 1;
            $result['files'][] = 'PHP CS Fixer failed with exit code ' . ($process->getExitCode() ?? 'unknown');
        }

        $unsupportedRules = [];
        if (!in_array($process->getExitCode(), [0, 8], true)) {
            $errorOutput = strtolower($process->getErrorOutput());
            foreach (array_keys(self::getRuleRegistry()) as $rule) {
                if (
                    str_contains($errorOutput, strtolower($rule))
                    && (
                        str_contains($errorOutput, 'invalid')
                        || str_contains($errorOutput, 'unknown')
                        || str_contains($errorOutput, 'does not exist')
                        || str_contains($errorOutput, 'cannot find')
                    )
                ) {
                    $unsupportedRules[] = $rule;
                }
            }
        }

        $result['unsupported_rules'] = $unsupportedRules;

        return $result;
    }

    /**
     * @return array{violations: int, files: array<int, string>, message: string}|null
     */
    private function checkAutoloadOptimization(ToolResolver $resolver): ?array
    {
        $composer = $resolver->resolve('composer');
        if ($composer === null) {
            return null;
        }

        $autoloadFile = $resolver->getProjectRoot() . '/vendor/composer/autoload_classmap.php';

        if (!file_exists($autoloadFile)) {
            return [
                'violations' => 1,
                'files' => [],
                'message' => 'Autoload not optimized — run "composer dump-autoload -o"',
            ];
        }

        return [
            'violations' => 0,
            'files' => [],
            'message' => '',
        ];
    }

    /**
     * @param  array<int, string>  $paths
     * @return array{violations: int, files: array<int, string>, reasons: array<int, string>, message: string}
     */
    private function checkConditionOrder(array $paths): array
    {
        $analyzer = new ConditionOrderAnalyzer();
        $violations = $analyzer->analyze($paths);

        if ($violations === []) {
            return [
                'violations' => 0,
                'files' => [],
                'reasons' => [],
                'message' => '',
            ];
        }

        $files = [];
        $reasons = [];
        foreach ($violations as $v) {
            $files[] = $v['file'] . ':' . $v['line'];
            $reasons[] = $v['message'];
        }

        return [
            'violations' => count($violations),
            'files' => $files,
            'reasons' => $reasons,
            'message' => sprintf(
                '%d condition order issues — cheaper conditions should come first',
                count($violations),
            ),
        ];
    }

    /**
     * @param  array<int, string>  $files
     * @param  array<int, string>  $messages
     * @param  array<int, string>  $reasons
     * @return array{0: Status, 1: array<array{type: ActionType, message: string, files: array<int, string>, reasons: array<int, string>}>|null}
     */
    private function evaluateViolations(int $violations, array $files, array $messages, array $reasons = []): array
    {
        $status = Status::Pass;
        $actions = null;

        if ($violations > 0) {
            $status = Status::Fail;
            $actions = [[
                'type' => ActionType::ImprovePerformance,
                'message' => implode('; ', $messages),
                'files' => array_slice($files, 0, 50),
                'reasons' => array_slice($reasons, 0, 50),
            ]];
        }

        return [$status, $actions];
    }
}
