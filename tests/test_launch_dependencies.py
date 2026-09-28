from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LaunchDependencyContractTests(unittest.TestCase):
    def test_runtime_dependency_manifest_declares_flask(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("Flask", requirements)

    def test_batch_launcher_bootstraps_from_manifest_with_python_module_pip(self):
        launch = (ROOT / "Launch.bat").read_text(encoding="utf-8").lower()
        self.assertIn("-m pip install", launch)
        self.assertIn("requirements.txt", launch)
        self.assertNotIn("pip install -e .", launch)

    def test_development_electron_path_includes_bundled_runtime(self):
        electron_main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8")
        self.assertIn(".bundled-runtime", electron_main)
        self.assertIn("developmentCandidates", electron_main)

    def test_packaging_installs_missing_runtime_dependencies(self):
        staging = (ROOT / "scripts" / "stage-python-runtime.js").read_text(encoding="utf-8")
        self.assertIn("requirements.txt", staging)
        self.assertIn("-m', 'pip', 'install", staging)


if __name__ == "__main__":
    unittest.main()
