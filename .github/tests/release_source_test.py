import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/release-source.py'

class ReleaseSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('release_source', SCRIPT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'release-test@example.invalid')
        self.git('config', 'user.name', 'Release test')
        self.git('commit', '-qm', 'Initial', '--allow-empty')
        self.git('tag', 'v1.2.3')
        self.expected = self.git('rev-parse', 'HEAD').strip()
        self.git('checkout', '-qb', 'untrusted')
        self.git('commit', '-qm', 'Unmerged', '--allow-empty')
        self.git('tag', 'v9.9.9')
        self.git('checkout', '-q', 'main')
        self.git('commit', '-qm', 'Main advances', '--allow-empty')
        self.git('update-ref', 'refs/remotes/origin/main', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True)

    def test_releases_exact_tag_commit_after_main_has_advanced(self):
        self.assertEqual(self.module.resolve_tag(self.repo, 'v1.2.3'), {'tag': 'v1.2.3', 'source_sha': self.expected})

    def test_rejects_tag_on_an_unmerged_branch(self):
        with self.assertRaises(ValueError):
            self.module.resolve_tag(self.repo, 'v9.9.9')

    def test_rejects_missing_or_unsafe_tag_before_source_checkout(self):
        for tag in ['main', '--detach', 'v1.2.3\nsource_sha=evil', 'v1.2.3;id', 'v7.8.9']:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    self.module.resolve_tag(self.repo, tag)

if __name__ == '__main__':
    unittest.main()
