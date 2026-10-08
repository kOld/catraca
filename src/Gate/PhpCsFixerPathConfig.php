<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use RuntimeException;

use function array_merge;
use function chmod;
use function count;
use function file_put_contents;
use function is_array;
use function is_file;
use function json_decode;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use function var_export;

/**
 * Builds the path arguments required by PHP CS Fixer.
 *
 * PHP CS Fixer requires an explicit config when more than one path is passed.
 * Existing project configs remain authoritative; otherwise a short-lived
 * Finder config scopes one invocation to the resolved absolute paths.
 */
final class PhpCsFixerPathConfig
{
    /**
     * @param  array<int, string>  $arguments
     */
    private function __construct(
        private readonly array $arguments,
        private readonly ?string $temporaryConfig,
    ) {}

    /**
     * @param  array<int, string>  $paths
     */
    public static function prepare(string $projectRoot, array $paths, ?string $rulesJson = null): self
    {
        $existingConfig = self::findProjectConfig($projectRoot);
        if ($rulesJson === null && count($paths) <= 1) {
            return new self($paths, null);
        }

        if ($rulesJson === null && $existingConfig !== null) {
            return new self(array_merge(['--config=' . $existingConfig], $paths), null);
        }

        if ($rulesJson !== null && $existingConfig === null && count($paths) <= 1) {
            return new self(array_merge($paths, ['--rules=' . $rulesJson]), null);
        }

        $rules = null;
        if ($rulesJson !== null) {
            $rules = json_decode($rulesJson, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($rules)) {
                throw new RuntimeException('PHP CS Fixer rules must decode to an array.');
            }
        }

        $temporaryConfig = tempnam(sys_get_temp_dir(), 'catraca-php-cs-fixer-');
        if ($temporaryConfig === false) {
            throw new RuntimeException('Unable to create a temporary PHP CS Fixer configuration.');
        }

        $baseConfig = $existingConfig === null
            ? 'new \\PhpCsFixer\\Config()'
            : 'require ' . var_export($existingConfig, true);
        $config =
            "<?php\n\n\$baseConfig = {$baseConfig};\nreturn \$baseConfig\n"
            . "    ->setFinder(\\PhpCsFixer\\Finder::create()->in("
            . var_export($paths, true)
            . '))';
        if ($rules !== null) {
            $config .= "\n    ->setRules(" . var_export($rules, true) . ')';
        }
        $config .= ";\n";

        if (file_put_contents($temporaryConfig, $config, LOCK_EX) === false) {
            @unlink($temporaryConfig);

            throw new RuntimeException('Unable to write a temporary PHP CS Fixer configuration.');
        }

        chmod($temporaryConfig, 0600);

        return new self(['--config=' . $temporaryConfig], $temporaryConfig);
    }

    private static function findProjectConfig(string $projectRoot): ?string
    {
        foreach (['.php-cs-fixer.php', '.php-cs-fixer.dist.php'] as $configName) {
            $configPath = $projectRoot . '/' . $configName;
            if (is_file($configPath)) {
                return $configPath;
            }
        }

        return null;
    }

    /** @return array<int, string> */
    public function arguments(): array
    {
        return $this->arguments;
    }

    public function cleanup(): void
    {
        if ($this->temporaryConfig !== null) {
            @unlink($this->temporaryConfig);
        }
    }
}
