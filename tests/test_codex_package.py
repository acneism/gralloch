"""Exercise package assembly without building or installing into a user profile."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[1]
SHELL = shutil.which('pwsh') or shutil.which('powershell')


@unittest.skipUnless(SHELL, 'PowerShell is required')
class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gralloch package ')
        self.addCleanup(self.temp.cleanup)
        self.repo = pathlib.Path(self.temp.name)
        for relative in ('scripts/install-codex.ps1', '.codex-plugin/plugin.json',
                         '.mcp.codex.json', '.agents/skills/gralloch/SKILL.md',
                         'README.md', 'docs/CODEX.md', 'LICENSE'):
            dest = self.repo / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE / relative, dest)
        for relative in ('bin/gralloch-mcp.exe', 'scripts/fixture.ps1',
                         'skills/fixture/SKILL.md', 'schemas/fixture.json',
                         'hooks/hooks.json', 'gralloch-mcp/target/secret.txt'):
            dest = self.repo / 'gralloch-plugin' / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b'fixture; never executed')
        (self.repo / '.codex').mkdir()
        (self.repo / '.codex/config.toml').write_text('private local settings')
        self.package = self.repo / '.codex-package/gralloch'

    def run_installer(self, *flags):
        return subprocess.run([SHELL, '-NoProfile', '-File',
                               str(self.repo / 'scripts/install-codex.ps1'),
                               '-SkipBuild', '-PackageOnly', *flags],
                              capture_output=True, timeout=30)

    def test_runtime_package_excludes_local_settings_hooks_and_build_files(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.package / '.codex-plugin/plugin.json').read_text())
        self.assertTrue((self.package / manifest['skills'] / 'gralloch/SKILL.md').is_file())
        self.assertTrue((self.package / 'gralloch-plugin/bin/gralloch-mcp.exe').is_file())
        self.assertTrue((self.package / manifest['mcpServers']).is_file())
        self.assertTrue((self.package / 'docs/CODEX.md').is_file())
        self.assertFalse((self.package / '.codex/config.toml').exists())
        self.assertFalse((self.package / 'gralloch-plugin/hooks').exists())
        self.assertFalse((self.package / 'gralloch-plugin/gralloch-mcp').exists())

    def test_refresh_removes_stale_runtime_files(self):
        self.assertEqual(self.run_installer().returncode, 0)
        stale = self.package / 'stale.txt'
        stale.write_text('old package file')
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertFalse(stale.exists())

    def test_unrecognized_directory_is_preserved(self):
        self.package.mkdir(parents=True)
        unrelated = self.package / 'keep.txt'
        unrelated.write_text('user data')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(unrelated.read_text(), 'user data')

    def test_missing_binary_is_reported_before_packaging(self):
        (self.repo / 'gralloch-plugin/bin/gralloch-mcp.exe').unlink()
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse(self.package.exists())

    def test_conflicting_build_flags_are_rejected(self):
        self.assertNotEqual(self.run_installer('-Yara').returncode, 0)
        self.assertFalse(self.package.exists())

    def test_installer_binds_mcp_to_installed_cache(self):
        installed = self.repo / 'installed cache with spaces'
        # A local Codex stub isolates this regression test from user settings.
        script = r'''
function codex {
    if ($args[1] -eq 'marketplace') { return }
    $source = Join-Path 'REPO_PATH' '.codex-package/gralloch'
    Copy-Item -LiteralPath $source -Destination 'INSTALLED_PATH' -Recurse
    @{ pluginId = 'gralloch@gralloch-codex'; installedPath = 'INSTALLED_PATH' } | ConvertTo-Json
}
$global:LASTEXITCODE = 0
& 'SCRIPT_PATH' -SkipBuild
'''
        for key, value in [('REPO_PATH', self.repo), ('INSTALLED_PATH', installed),
                           ('SCRIPT_PATH', self.repo / 'scripts/install-codex.ps1')]:
            script = script.replace(key, str(value).replace("'", "''"))
        result = subprocess.run([SHELL, '-NoProfile', '-Command', script],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        source_config = json.loads((self.package / '.mcp.codex.json').read_text())
        installed_config = json.loads((installed / '.mcp.codex.json').read_text())
        self.assertEqual(source_config, installed_config)
        server = pathlib.Path(installed_config['mcpServers']['gralloch']['command'])
        self.assertTrue(server.is_file())
        self.assertTrue(server.is_relative_to(installed))


if __name__ == '__main__':
    unittest.main()
