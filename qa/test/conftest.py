# conftest.py — pytest find this file by name, load before all tests, no import needed.
# Two jobs:
#   1. gevent patch — must run before ssl imported (jwt pulls ssl in). patch here = first.
#   2. hooks — collect results, print summary after each run. reset between runs (main_test calls pytest many times).
try:
    from gevent import monkey as _monkey
    _monkey.patch_all()
except ImportError:
    pass

# Ensure qa/ is on sys.path so every test file (including perf/) can
# do `from qa_utils import ...` without carrying its own path-setup block.
import sys as _sys
from pathlib import Path as _Path
_QA_ROOT = _Path(__file__).resolve().parent.parent  # qa/test/ → qa/
if str(_QA_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_QA_ROOT))

import pytest
from pathlib import Path


class TestReporter:
    """Custom reporter for test execution summary."""
    
    def __init__(self):
        self.results = []
        self.use_case = "Positive Test Cases"
        self.total_tests = 0
        self.passed = 0
        self.failed = 0
        self.failures = []

    def reset(self, session):
        """Reset reporter state for each pytest session.

        Needed because main_test.py invokes pytest.main() multiple times
        in the same process.
        """
        self.results = []
        self.total_tests = 0
        self.passed = 0
        self.failed = 0
        self.failures = []

        # Derive a readable use-case label from current test target.
        args = getattr(session.config, "args", [])
        if args:
            file_name = Path(args[0]).name.lower()
            if "pos_case" in file_name:
                self.use_case = "Positive Test Cases"
            elif "neg_case" in file_name:
                self.use_case = "Negative Test Cases"
            elif "corner_case" in file_name:
                self.use_case = "Corner Test Cases"
            elif "oauth_case" in file_name:
                self.use_case = "OAuth2 Functional Tests"
            elif "security_case" in file_name:
                self.use_case = "Security Tests"
            else:
                self.use_case = "Test Cases"
    
    def add_result(self, test_name, status, error_info=None):
        """Record test result."""
        self.results.append({
            'name': test_name,
            'status': status,
            'error': error_info
        })
        self.total_tests += 1
        if status == 'PASSED':
            self.passed += 1
        elif status == 'FAILED':
            self.failed += 1
            self.failures.append({
                'test': test_name,
                'error': error_info
            })
    
    def print_summary(self):
        """Print formatted test summary."""
        print("=" * 80)
        print(f"USE CASE: {self.use_case}")
        print("=" * 80)
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        
        if self.results:
            print("-" * 80)
            print("TEST RESULTS:")
            print("-" * 80)
            for idx, result in enumerate(self.results, 1):
                print(f"{idx}. [{result['status']}] {result['name']}")
                if result['error']:
                    print(f"   Error: {result['error']}")
        
        if self.failures:
            print("-" * 80)
            print("FAILURES:")
            print("-" * 80)
            for failure in self.failures:
                print(f"Test: {failure['test']}")
                if failure['error']:
                    print("Details:")
                    print(f"{failure['error']}")
        
        print("=" * 80)
        status = "PASSED" if self.failed == 0 else "FAILED"
        print(f"OVERALL STATUS: {status}")
        print("=" * 80)


_reporter = TestReporter()


def pytest_sessionstart(session):
    """Reset reporter state at the start of each pytest session."""
    _reporter.reset(session)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logreport(report):
    """Capture test results."""
    if report.when == "call":
        test_name = report.nodeid.split("::")[-1]
        if report.passed:
            _reporter.add_result(test_name, 'PASSED')
        elif report.failed:
            error_msg = str(report.longrepr).splitlines()[0] if report.longrepr else "Unknown error"
            _reporter.add_result(test_name, 'FAILED', error_msg)


def pytest_sessionfinish(session, exitstatus):
    """Print summary when session ends."""
    _reporter.print_summary()
