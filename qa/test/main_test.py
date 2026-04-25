import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


class SuiteResultCollector:
    """Collect per-test outcomes for a single pytest run."""

    def __init__(self):
        self.passed = 0
        self.failed = 0

    def pytest_runtest_logreport(self, report):
        """Track only final test call outcomes."""
        if report.when != "call":
            return

        if report.passed:
            self.passed += 1
        elif report.failed:
            self.failed += 1


class SuiteExecutor:
    """Execute test suites and display results."""
    
    def __init__(self):
        self.test_dir = Path(__file__).resolve().parent
        self.test_suites = [
            {
                'name': 'Positive Test Cases',
                'path': str(self.test_dir / 'pos_case.py'),
                'description': 'Positive Scenarios'
            },
            {
                'name': 'Negative Test Cases',
                'path': str(self.test_dir / 'neg_case.py'),
                'description': 'Security & Attack Scenarios'
            },
            {
                'name': 'Corner Cases',
                'path': str(self.test_dir / 'corner_case.py'),
                'description': 'Boundary & Edge Cases'
            },
            {
                'name': 'Security Tests',
                'path': str(self.test_dir / 'security_case.py'),
                'description': 'Cryptographic Attack Vectors & Protocol Security'
            },
            {
                'name': 'OAuth2 Functional Tests',
                'path': str(self.test_dir / 'oauth_case.py'),
                'description': 'OAuth2 PKCE & Simple Authorization Code Flow'
            },
        ]
    
    def print_header(self):
        """Print execution header."""
        print("=" * 90)
        print("\t\tTEST SUITE EXECUTOR")
        print("=" * 90)
        print(f"Test Directory: {self.test_dir}")
        print(f"Total Test Suites: {len(self.test_suites)}")
        print("=" * 90 )
    
    def run_suite(self, suite):
        """Run a single test suite."""
        print(f"{'=' * 90}")
        print(f"Running: {suite['name']}")
        print(f"Description: {suite['description']}")
        print(f"{'=' * 90}")

        collector = SuiteResultCollector()
        
        # Run pytest with the specified file
        exit_code = pytest.main([
            suite['path'],
            '-v',
            '--tb=short',
            '--color=yes'
        ], plugins=[collector])
        
        return {
            'suite_passed': exit_code == 0,
            'tests_passed': collector.passed,
            'tests_failed': collector.failed,
        }
    
    def print_footer(self, results):
        """Print execution footer with summary."""
        passed_suites = sum(1 for r in results if r['suite_passed'])
        total_suites = len(results)
        total_tests_passed = sum(r['tests_passed'] for r in results)
        total_tests_failed = sum(r['tests_failed'] for r in results)
        total_tests = total_tests_passed + total_tests_failed
        
        print( "=" * 90)
        print("\t\tFINAL TEST EXECUTION SUMMARY")
        print("=" * 90)
        print(f"Total Test Suites: {total_suites}")
        print(f"Passed Suites: {passed_suites}")
        print(f"Failed Suites: {total_suites - passed_suites}")
        print("-" * 90)
        print(f"Total Tests: {total_tests}")
        print(f"Passed Tests: {total_tests_passed}")
        print(f"Failed Tests: {total_tests_failed}")
        print("\nTest Suite Results:")
        print("-" * 90)
        
        for i, (suite, result) in enumerate(zip(self.test_suites, results), 1):
            status = "PASSED" if result['suite_passed'] else "FAILED"
            print(
                f"{i}. {suite['name']:<40} [{status}] "
                f"(passed={result['tests_passed']}, failed={result['tests_failed']})"
            )
        
        print("=" * 90)
        
        if all(r['suite_passed'] for r in results):
            print("\t\tALL TEST SUITES PASSED")
            print("=" * 90 )
            return 0
        else:
            print("\t\tSOME TEST SUITES FAILED")
            print("=" * 90 )
            return 1
    
    def execute(self):
        """Execute all test suites."""
        self.print_header()
        
        results = []
        for suite in self.test_suites:
            try:
                result = self.run_suite(suite)
                results.append(result)
            except Exception as e:
                print(f"\n\t\t✗ Error running {suite['name']}: {str(e)}")
                results.append({
                    'suite_passed': False,
                    'tests_passed': 0,
                    'tests_failed': 1,
                })
        
        return self.print_footer(results)


def main():
    """Entry point for the test executor."""
    executor = SuiteExecutor()
    exit_code = executor.execute()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
