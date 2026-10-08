<?php

namespace B7S\Catraca;

use function array_key_exists;
use function count;
use function is_array;
use function is_string;

class CsFixerResultParser
{
    /**
     * @return array{violations: int, files: array<int, string>, rule_counts: array<string, int>, valid: bool}
     */
    public static function parseJsonOutput(string $output): array
    {
        $files = [];
        $ruleCounts = [];
        $valid = false;

        $data = json_decode($output, true);
        if (is_array($data) && array_key_exists('files', $data) && is_array($data['files'])) {
            $valid = true;
            $fileEntries = $data['files'];

            foreach ($fileEntries as $value) {
                if (!is_array($value)) {
                    $valid = false;

                    break;
                }
                $filePath = $value['name'] ?? $value['file'] ?? null;
                if (!is_string($filePath) || $filePath === '') {
                    $valid = false;

                    break;
                }
                $files[] = $filePath;

                $appliedFixers = $value['appliedFixers'] ?? [];
                if (!is_array($appliedFixers)) {
                    $valid = false;

                    break;
                }
                foreach ($appliedFixers as $fixer) {
                    if (!is_string($fixer) || $fixer === '') {
                        $valid = false;

                        break 2;
                    }
                    $ruleCounts[$fixer] = ($ruleCounts[$fixer] ?? 0) + 1;
                }
            }
        }

        return [
            'violations' => count($files),
            'files' => $files,
            'rule_counts' => $ruleCounts,
            'valid' => $valid,
        ];
    }
}
