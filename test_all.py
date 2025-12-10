import os
import sys
import unittest


def main():
    root = os.path.abspath(os.path.dirname(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)

    print("Running all tests in tests/ ...")
    suite = unittest.defaultTestLoader.discover(os.path.join(root, "tests"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(
        f"Summary: запущего {result.testsRun} тестов, ошибок={len(result.failures)}"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
