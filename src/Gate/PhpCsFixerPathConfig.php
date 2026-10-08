<?php

declare(strict_types=1);

namespace B7S\Catraca\Gate;

use function chmod;
use function count;
use function file_put_contents;
use function is_file;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use function var_export;

/**
 * Builds the path arguments required by PHP CS Fixer.
 *
 * PHP CS Fixer requires an explicit config when more than one path is passed.
 * Existing project configs remain authoritative; otherwise a short-lived
 * empty config enables native path resolution for one invocation.
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
        $temporaryConfig = null;
        $arguments = [];

        if ($existingConfig !== null && $rulesJson !== null) {
            $temporaryConfig = self::createConfigWithRules($existingConfig, $rulesJson);
            $arguments[] = '--config=' . $temporaryConfig;
        } elseif ($existingConfig !== null) {
            $arguments[] = '--config=' . $existingConfig;
        } elseif (count($paths) > 1) {
            $temporaryConfig = self::createConfigWithRules(null, null);
            $arguments[] = '--config=' . $temporaryConfig;
        }

        if ($rulesJson !== null && $temporaryConfig === null) {
            $arguments[] = '--rules=' . $rulesJson;
        }

        return new self([...$arguments, ...$paths], $temporaryConfig);
    }

    private static function createConfigWithRules(?string $existingConfig, ?string $rulesJson): string
    {
        $temporaryConfig = tempnam(sys_get_temp_dir(), 'catraca-php-cs-fixer-');
        if ($temporaryConfig === false) {
            throw new \RuntimeException('Unable to create a temporary PHP CS Fixer configuration.');
        }

        $config = $existingConfig === null
            ? '$config = new \\PhpCsFixer\\Config();'
            : '$config = require ' . var_export($existingConfig, true) . ';';
        if ($rulesJson !== null) {
            $config .=
                "\n\$config = \$config->setRules(json_decode("
                . var_export($rulesJson, true)
                . ', true, 512, JSON_THROW_ON_ERROR));';
        }
        $config = "<?php\n\n{$config}\nreturn \$config;\n";

        if (file_put_contents($temporaryConfig, $config, LOCK_EX) === false) {
            @unlink($temporaryConfig);

            throw new \RuntimeException('Unable to write a temporary PHP CS Fixer configuration.');
        }

        chmod($temporaryConfig, 0600);

        return $temporaryConfig;
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
