import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release_notes', Path(__file__).resolve().parents[1] / 'render-release-notes.py')
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'docs/releases'
        self.folder.mkdir(parents=True)
        for lang, text in (('en', 'English fixes'), ('ru', 'Исправления')):
            (self.folder / f'v1.0.1.{lang}.md').write_text(text, encoding='utf-8')

    def render(self, **changes):
        args = dict(root=self.root, tag='v1.0.1', source='a' * 40, producer='b' * 40,
                    handoff='c' * 40, asset='foxhole-core-v1.0.1.tar.gz', archive_sha256='d' * 64)
        args.update(changes)
        return notes.render(**args)

    def test_both_languages_precede_separate_provenance(self):
        body = self.render()
        self.assertLess(body.index('English fixes'), body.index('Исправления'))
        self.assertLess(body.index('Исправления'), body.index('## Provenance'))
        self.assertIn('b' * 40, body)

    def test_missing_versioned_notes_fail_closed(self):
        (self.folder / 'v1.0.1.ru.md').unlink()
        with self.assertRaises(FileNotFoundError):
            self.render()

    def test_traversal_and_unbounded_notes_are_rejected(self):
        with self.assertRaises(ValueError):
            self.render(tag='../v1.0.1')
        (self.folder / 'v1.0.1.en.md').write_text('x' * 65537)
        with self.assertRaises(ValueError):
            self.render()

    def test_archive_and_commit_injection_are_rejected(self):
        for kwargs in ({'asset': 'foxcore-android-v1.0.1.tar.gz'}, {'source': 'a' * 40 + '\n'},
                       {'archive_sha256': 'z' * 64}, {'producer': 'short'}):
            with self.assertRaises(ValueError):
                self.render(**kwargs)

    def test_notes_hash_is_bound_without_modifying_source_notes(self):
        original = (self.folder / 'v1.0.1.en.md').read_bytes()
        first = self.render()
        self.assertEqual((self.folder / 'v1.0.1.en.md').read_bytes(), original)
        (self.folder / 'v1.0.1.en.md').write_text('Updated fixes')
        self.assertNotEqual(first, self.render())

    def test_symlink_notes_are_rejected(self):
        note = self.folder / 'v1.0.1.ru.md'
        note.unlink()
        note.symlink_to(self.folder / 'v1.0.1.en.md')
        with self.assertRaises(ValueError):
            self.render()


if __name__ == '__main__':
    unittest.main()
