"""Local tests only: deterministic bytes and inert marker application behavior."""

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_package import build_package


ROOT = Path(__file__).resolve().parents[1]
MARKER = "0123456789abcdef" * 2


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def build(self, name="app.zip", **kwargs):
        output = self.directory / name
        result = build_package(ROOT / "app", output, MARKER, **kwargs)
        return output, result

    def test_deterministic_zip_has_only_expected_files_and_fixed_metadata(self):
        first, manifest = self.build("one.zip")
        second, second_manifest = self.build("two.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(manifest, second_manifest)
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), ["lambda_function.py", "release.json"])
            self.assertEqual(json.loads(archive.read("release.json")), {"release_marker": MARKER})
            for entry in archive.infolist():
                self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(entry.external_attr >> 16, 0o100644)

    def test_marker_is_the_only_runtime_response_even_for_untrusted_payload(self):
        output, _ = self.build()
        destination = self.directory / "unpacked"
        with zipfile.ZipFile(output) as archive:
            archive.extractall(destination)
        spec = importlib.util.spec_from_file_location("study_lambda", destination / "lambda_function.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.lambda_handler({"command": "ignored", "marker": "ignored"}, None),
                         {"release_marker": MARKER})

    def test_boundary_has_inert_constant_and_preserves_handler(self):
        plain, _ = self.build("plain.zip")
        boundary, manifest = self.build("boundary.zip", boundary=True)
        self.assertNotEqual(plain.read_bytes(), boundary.read_bytes())
        self.assertTrue(manifest["boundary_illustration"])
        with zipfile.ZipFile(boundary) as archive:
            source = archive.read("lambda_function.py").decode()
            self.assertIn('DEMO_INSECURE_CONFIGURATION = "illustration_only"', source)
            self.assertNotIn("eval(", source)
            self.assertNotIn("exec(", source)

    def test_rejects_variable_length_or_injection_markers(self):
        for marker in ("", "0" * 31, "0" * 33, "A" * 32, "$(echo surprise)", "0" * 32 + "\n"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                build_package(ROOT / "app", self.directory / "bad.zip", marker)

    def test_never_overwrites_input_or_output(self):
        output, _ = self.build()
        original = output.read_bytes()
        with self.assertRaises(ValueError):
            build_package(ROOT / "app", output, MARKER)
        self.assertEqual(output.read_bytes(), original)

    def test_rejects_source_symlink(self):
        source = self.directory / "source"
        source.mkdir()
        (source / "lambda_function.py").symlink_to(ROOT / "app/lambda_function.py")
        with self.assertRaises(ValueError):
            build_package(source, self.directory / "bad.zip", MARKER)


if __name__ == "__main__":
    unittest.main()
