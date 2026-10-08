<?php

declare(strict_types=1);

namespace B7S\Catraca\Tests;

use B7S\Catraca\Gate\DependencyAuditScanner;
use PHPUnit\Framework\TestCase;

use function chmod;
use function file_exists;
use function file_put_contents;
use function getenv;
use function is_dir;
use function mkdir;
use function putenv;
use function rmdir;
use function scandir;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

final class DependencyAuditScannerTest extends TestCase
{
    private string $tmpDir;

    private string $originalPath;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/catraca-dependency-audit-' . uniqid('', true);
        $this->originalPath = (string) getenv('PATH');
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        putenv('PATH=' . $this->originalPath);

        if (is_dir($this->tmpDir)) {
            $this->removeTree($this->tmpDir);
        }
    }

    public function test_composer_audit_flattens_nested_package_advisories(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":{"acme/high":[{"title":"High issue","cve":"CVE-2026-0001","severity":"high"}],"acme/critical":[{"title":"Critical issue","cve":null,"severity":"critical"}]}}'
            exit 1
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertSame(2, $result['critical']);
        self::assertSame(['High issue (CVE-2026-0001)', 'Critical issue (N/A)'], $result['findings']);
    }

    public function test_composer_audit_fails_closed_on_malformed_json(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{malformed'
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('invalid JSON', $result['findings'][0]);
    }

    public function test_composer_audit_fails_closed_on_process_error(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' 'composer unavailable token=super-secret-value' >&2
            exit 2
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('status 2', $result['findings'][0]);
        self::assertStringContainsString('invalid JSON', $result['findings'][0]);
        self::assertStringContainsString('token=[redacted]', $result['findings'][0]);
        self::assertStringNotContainsString('super-secret-value', $result['findings'][0]);
    }

    public function test_composer_audit_redacts_authenticated_urls_and_bearer_credentials(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{malformed'
            printf '%s\n' 'repository=https://ci-user:ci-password@example.com Authorization: Bearer bearer-secret' >&2
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('https://[redacted]@example.com', $result['findings'][0]);
        self::assertStringContainsString('Authorization: Bearer [redacted]', $result['findings'][0]);
        self::assertStringNotContainsString('ci-user', $result['findings'][0]);
        self::assertStringNotContainsString('ci-password', $result['findings'][0]);
        self::assertStringNotContainsString('bearer-secret', $result['findings'][0]);
    }

    public function test_composer_audit_requires_the_advisories_key(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"abandoned":[]}'
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('invalid advisory payload', $result['findings'][0]);
    }

    public function test_composer_audit_fails_closed_on_malformed_nested_advisory(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":{"acme/package":[null]}}'
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('invalid advisory payload', $result['findings'][0]);
    }

    public function test_composer_audit_fails_closed_when_advisory_severity_is_missing(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":{"acme/package":[{"title":"Missing severity"}]}}'
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('invalid advisory payload', $result['findings'][0]);
    }

    public function test_composer_audit_fails_closed_when_advisory_severity_is_unknown(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":{"acme/package":[{"severity":"unknown"}]}}'
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('invalid advisory payload', $result['findings'][0]);
    }

    public function test_composer_audit_keeps_valid_lower_severity_advisories_nonblocking(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":{"acme/package":[{"title":"Low issue","severity":"low"}]}}'
            exit 1
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertSame([], $result['findings']);
        self::assertSame(0, $result['critical']);
    }

    public function test_composer_audit_reports_legacy_abandoned_exit_code(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":[],"abandoned":{"57":{"id":-1}}}'
            exit 2
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertSame(0, $result['critical']);
        self::assertSame(['composer audit reported abandoned package policy findings'], $result['findings']);
    }

    public function test_composer_audit_fails_closed_on_exit_one_without_reported_findings(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":[],"abandoned":[]}'
            exit 1
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertNotSame([], $result['findings']);
        self::assertStringContainsString('reported no audit findings', $result['findings'][0]);
    }

    public function test_composer_audit_reports_dependency_policy_filter_findings(): void
    {
        $composer = $this->writeExecutable('composer', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"advisories":[],"abandoned":[],"filter":{"acme/package":[{"listName":"malware"}]}}'
            exit 1
            SH);

        $result = (new DependencyAuditScanner($this->tmpDir))->runComposerAudit($composer);

        self::assertSame(['composer audit reported dependency policy findings'], $result['findings']);
    }

    public function test_npm_audit_accepts_exit_one_with_a_valid_report(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"vulnerabilities":{"lodash":{"severity":"high","via":[{"title":"Prototype pollution"}]}}}'
            exit 1
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertCount(1, $findings);
        self::assertIsString($findings[0]);
        self::assertStringContainsString('[high] lodash: Prototype pollution', $findings[0]);
    }

    public function test_npm_audit_fails_closed_on_exit_one_without_vulnerability_findings(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"vulnerabilities":{}}'
            exit 1
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertStringContainsString('reported no audit findings', $findings[0]);
    }

    public function test_npm_audit_fails_closed_on_malformed_json(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{malformed'
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertIsString($findings[0]);
        self::assertStringContainsString('invalid JSON', $findings[0]);
    }

    public function test_npm_audit_fails_closed_on_process_error(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' 'npm unavailable' >&2
            exit 2
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertIsString($findings[0]);
        self::assertStringContainsString('exited with status 2', $findings[0]);
    }

    public function test_npm_audit_fails_closed_when_vulnerability_severity_is_missing(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"vulnerabilities":{"lodash":{"via":[]}}}'
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertStringContainsString('invalid vulnerability severity', $findings[0]);
    }

    public function test_npm_audit_fails_closed_when_vulnerability_severity_is_unknown(): void
    {
        $this->write('package.json', '{}');
        $this->write('package-lock.json', '{}');
        $npm = $this->writeExecutable('npm', <<<'SH'
            #!/bin/sh
            printf '%s\n' '{"vulnerabilities":{"lodash":{"severity":"unknown"}}}'
            SH);
        $this->prependPath($npm);

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertStringContainsString('invalid vulnerability severity', $findings[0]);
    }

    public function test_npm_audit_rejects_an_unsupported_yarn_lockfile(): void
    {
        $this->write('package.json', '{}');
        $this->write('yarn.lock', '# yarn lockfile');

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertIsString($findings[0]);
        self::assertStringContainsString('unsupported yarn.lock', $findings[0]);
    }

    public function test_npm_audit_rejects_a_missing_lockfile(): void
    {
        $this->write('package.json', '{}');

        $findings = (new DependencyAuditScanner($this->tmpDir))->checkNpmAudit();

        self::assertNotSame([], $findings);
        self::assertIsString($findings[0]);
        self::assertStringContainsString('without package-lock.json', $findings[0]);
    }

    private function write(string $relative, string $content): void
    {
        $path = $this->tmpDir . '/' . $relative;
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents($path, $content);
    }

    private function writeExecutable(string $relative, string $content): string
    {
        $this->write($relative, $content);
        $path = $this->tmpDir . '/' . $relative;
        chmod($path, 0755);

        return $path;
    }

    private function prependPath(string $binary): void
    {
        putenv('PATH=' . dirname($binary) . ':' . $this->originalPath);
    }

    private function removeTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $dir . '/' . $entry;
            if (is_dir($path)) {
                $this->removeTree($path);
            } elseif (file_exists($path)) {
                unlink($path);
            }
        }

        if (is_dir($dir)) {
            rmdir($dir);
        }
    }
}
