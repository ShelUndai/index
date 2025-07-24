"""
Real URL Classification Test Suite
Tests the enhanced URL classifier against known real-world URLs
"""

import asyncio
import logging
import time
from typing import Dict, List, Tuple
from dataclasses import dataclass
import json

# Import the enhanced classifier
from url_classifier import (
    EnhancedInventoryURLClassificationManager, 
    ClassificationConfig,
    URLClassificationResult
)

# Configure logging for testing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TestCase:
    """Test case structure for validation"""
    url: str
    expected_type: str
    expected_subtype: str = None
    expected_technologies: List[str] = None
    description: str = ""
    
    def __post_init__(self):
        if self.expected_technologies is None:
            self.expected_technologies = []

class URLClassifierTester:
    """Test suite for URL classification accuracy"""
    
    def __init__(self):
        # Test configuration optimized for testing
        self.config = ClassificationConfig(
            max_concurrent=20,  # Lower for testing
            timeout=15,
            content_limit_kb=200,  # Smaller for faster testing
            verbose_logging=True,
            enable_caching=True,
            min_confidence_threshold=0.7
        )
        
        self.test_cases = self._create_test_cases()
        self.results = []
        
    def _create_test_cases(self) -> List[TestCase]:
        """Create comprehensive test cases with known URLs"""
        return [
            # REST APIs
            TestCase(
                url="https://jsonplaceholder.typicode.com/posts",
                expected_type="API",
                expected_subtype="REST",
                description="JSON Placeholder REST API"
            ),
            TestCase(
                url="https://api.github.com/users/octocat",
                expected_type="API",
                expected_subtype="REST",
                description="GitHub REST API"
            ),
            TestCase(
                url="https://httpbin.org/json",
                expected_type="API",
                expected_subtype="REST",
                description="HTTPBin JSON endpoint"
            ),
            TestCase(
                url="https://reqres.in/api/users",
                expected_type="API",
                expected_subtype="REST",
                description="ReqRes test API"
            ),
            
            # GraphQL APIs
            TestCase(
                url="https://api.github.com/graphql",
                expected_type="API",
                expected_subtype="GraphQL",
                description="GitHub GraphQL API"
            ),
            
            # React Applications
            TestCase(
                url="https://reactjs.org",
                expected_type="UI",
                expected_subtype="React",
                expected_technologies=["React"],
                description="React official website"
            ),
            TestCase(
                url="https://create-react-app.dev",
                expected_type="UI",
                expected_subtype="React",
                expected_technologies=["React"],
                description="Create React App documentation"
            ),
            
            # Angular Applications
            TestCase(
                url="https://angular.io",
                expected_type="UI",
                expected_subtype="Angular",
                expected_technologies=["Angular"],
                description="Angular official website"
            ),
            
            # Vue.js Applications
            TestCase(
                url="https://vuejs.org",
                expected_type="UI",
                expected_subtype="Vue.js",
                expected_technologies=["Vue.js"],
                description="Vue.js official website"
            ),
            
            # Next.js Applications
            TestCase(
                url="https://nextjs.org",
                expected_type="UI",
                expected_subtype="Next.js",
                expected_technologies=["Next.js", "React"],
                description="Next.js official website"
            ),
            
            # Regular websites (non-framework)
            TestCase(
                url="https://example.com",
                expected_type="UI",
                description="Simple HTML website"
            ),
            TestCase(
                url="https://www.google.com",
                expected_type="UI",
                description="Google homepage"
            ),
            TestCase(
                url="https://stackoverflow.com",
                expected_type="UI",
                description="Stack Overflow"
            ),
            
            # WordPress sites
            TestCase(
                url="https://wordpress.org",
                expected_type="UI",
                expected_technologies=["WordPress"],
                description="WordPress.org website"
            ),
            
            # Node.js/Express backends
            TestCase(
                url="https://nodejs.org/api/",
                expected_type="UI",  # Documentation site, not API
                expected_technologies=["Node.js"],
                description="Node.js API documentation"
            ),
            
            # File endpoints
            TestCase(
                url="https://www.w3.org/WAI/WCAG21/wcag.pdf",
                expected_type="FILE",
                description="PDF file"
            ),
            
            # Redirects
            TestCase(
                url="http://github.com",  # Redirects to HTTPS
                expected_type="REDIRECT",
                description="HTTP to HTTPS redirect"
            ),
            
            # Error cases
            TestCase(
                url="https://httpbin.org/status/404",
                expected_type="ERROR",
                description="404 Not Found"
            ),
            TestCase(
                url="https://httpbin.org/status/500",
                expected_type="ERROR",
                description="500 Internal Server Error"
            ),
            TestCase(
                url="https://thisdomaindoesnotexist12345.com",
                expected_type="ERROR",
                description="Domain not found"
            ),
            
            # Edge cases
            TestCase(
                url="invalid-url-without-scheme",
                expected_type="ERROR",
                description="Invalid URL format"
            ),
            TestCase(
                url="https://httpbin.org/delay/20",  # Will timeout
                expected_type="ERROR",
                description="Timeout test"
            ),
        ]
    
    async def run_tests(self) -> Dict:
        """Run all test cases and return results"""
        logger.info(f"Starting test suite with {len(self.test_cases)} test cases")
        
        # Prepare URLs for classification
        test_urls = [(i, case.url) for i, case in enumerate(self.test_cases)]
        
        # Create manager
        manager = EnhancedInventoryURLClassificationManager(self.config)
        
        def get_test_urls():
            return test_urls
        
        def mock_update_callback(updates):
            # Store results for analysis
            for test_id, classification_data in updates:
                self.results.append((test_id, classification_data))
        
        def progress_callback(current, total, result):
            if current % 5 == 0:
                logger.info(f"Test progress: {current}/{total}")
        
        # Run classification
        start_time = time.time()
        stats = await manager.update_inventory_classifications(
            get_urls_callback=get_test_urls,
            update_callback=mock_update_callback,
            progress_callback=progress_callback
        )
        test_duration = time.time() - start_time
        
        # Analyze results
        analysis = self._analyze_results()
        analysis.update({
            'test_duration_seconds': test_duration,
            'performance_stats': stats
        })
        
        return analysis
    
    def _analyze_results(self) -> Dict:
        """Analyze test results and calculate accuracy metrics"""
        total_tests = len(self.test_cases)
        correct_type = 0
        correct_subtype = 0
        correct_technologies = 0
        
        detailed_results = []
        failures = []
        
        # Sort results by test ID
        sorted_results = sorted(self.results, key=lambda x: x[0])
        
        for test_id, classification_data in sorted_results:
            test_case = self.test_cases[test_id]
            
            # Extract classification results
            actual_type = classification_data.get('classification_type')
            actual_subtype = classification_data.get('classification_subtype')
            actual_technologies = json.loads(classification_data.get('technologies', '[]') or '[]')
            confidence = classification_data.get('confidence_score', 0)
            
            # Check type accuracy
            type_correct = actual_type == test_case.expected_type
            if type_correct:
                correct_type += 1
            
            # Check subtype accuracy (only if expected)
            subtype_correct = True
            if test_case.expected_subtype:
                subtype_correct = actual_subtype == test_case.expected_subtype
                if subtype_correct:
                    correct_subtype += 1
            
            # Check technology detection (if expected technologies specified)
            tech_correct = True
            detected_expected_techs = []
            if test_case.expected_technologies:
                detected_expected_techs = [
                    tech for tech in test_case.expected_technologies 
                    if tech in actual_technologies
                ]
                tech_correct = len(detected_expected_techs) > 0
                if tech_correct:
                    correct_technologies += 1
            
            # Overall correctness
            overall_correct = type_correct and subtype_correct and tech_correct
            
            result_detail = {
                'url': test_case.url,
                'description': test_case.description,
                'expected': {
                    'type': test_case.expected_type,
                    'subtype': test_case.expected_subtype,
                    'technologies': test_case.expected_technologies
                },
                'actual': {
                    'type': actual_type,
                    'subtype': actual_subtype,
                    'technologies': actual_technologies
                },
                'correct': {
                    'type': type_correct,
                    'subtype': subtype_correct,
                    'technologies': tech_correct,
                    'overall': overall_correct
                },
                'confidence': confidence,
                'detected_expected_techs': detected_expected_techs
            }
            
            detailed_results.append(result_detail)
            
            if not overall_correct:
                failures.append(result_detail)
        
        # Calculate accuracy percentages
        type_accuracy = (correct_type / total_tests) * 100
        
        # Subtype accuracy (only for tests that specified expected subtype)
        tests_with_subtype = sum(1 for case in self.test_cases if case.expected_subtype)
        subtype_accuracy = (correct_subtype / tests_with_subtype) * 100 if tests_with_subtype > 0 else 0
        
        # Technology accuracy (only for tests that specified expected technologies)
        tests_with_tech = sum(1 for case in self.test_cases if case.expected_technologies)
        tech_accuracy = (correct_technologies / tests_with_tech) * 100 if tests_with_tech > 0 else 0
        
        return {
            'summary': {
                'total_tests': total_tests,
                'type_accuracy_percent': round(type_accuracy, 1),
                'subtype_accuracy_percent': round(subtype_accuracy, 1),
                'technology_accuracy_percent': round(tech_accuracy, 1),
                'tests_with_subtype_expectations': tests_with_subtype,
                'tests_with_technology_expectations': tests_with_tech,
                'failures_count': len(failures)
            },
            'detailed_results': detailed_results,
            'failures': failures
        }
    
    def print_results(self, analysis: Dict):
        """Print comprehensive test results"""
        print("\n" + "="*80)
        print("URL CLASSIFICATION TEST RESULTS")
        print("="*80)
        
        summary = analysis['summary']
        print(f"Total tests: {summary['total_tests']}")
        print(f"Test duration: {analysis['test_duration_seconds']:.1f} seconds")
        print(f"Processing rate: {summary['total_tests'] / analysis['test_duration_seconds']:.1f} URLs/sec")
        print()
        
        print("ACCURACY METRICS:")
        print(f"  Type accuracy: {summary['type_accuracy_percent']}%")
        print(f"  Subtype accuracy: {summary['subtype_accuracy_percent']}% ({summary['tests_with_subtype_expectations']} tests)")
        print(f"  Technology accuracy: {summary['technology_accuracy_percent']}% ({summary['tests_with_technology_expectations']} tests)")
        print(f"  Failed tests: {summary['failures_count']}")
        print()
        
        # Performance stats
        perf = analysis['performance_stats']
        print("PERFORMANCE METRICS:")
        print(f"  Header-only classification: {perf['header_efficiency_percent']:.1f}%")
        print(f"  Cache hit rate: {perf['cache_hit_rate_percent']:.1f}%")
        print(f"  Error rate: {perf['error_rate_percent']:.1f}%")
        print(f"  Average confidence: {perf['average_confidence']:.3f}")
        print()
        
        # Show detailed results for key test cases
        print("DETAILED RESULTS (sample):")
        for i, result in enumerate(analysis['detailed_results'][:10]):
            status = "✓" if result['correct']['overall'] else "✗"
            print(f"  {status} {result['url']}")
            print(f"    Expected: {result['expected']['type']}/{result['expected']['subtype']}")
            print(f"    Actual: {result['actual']['type']}/{result['actual']['subtype']} (confidence: {result['confidence']:.2f})")
            if result['actual']['technologies']:
                print(f"    Technologies: {result['actual']['technologies']}")
            print()
        
        if len(analysis['detailed_results']) > 10:
            print(f"    ... and {len(analysis['detailed_results']) - 10} more results")
        
        # Show failures
        if analysis['failures']:
            print("\nFAILURES ANALYSIS:")
            for failure in analysis['failures']:
                print(f"  ✗ {failure['url']}")
                print(f"    Description: {failure['description']}")
                print(f"    Expected: {failure['expected']['type']}/{failure['expected']['subtype']}")
                print(f"    Actual: {failure['actual']['type']}/{failure['actual']['subtype']}")
                print(f"    Confidence: {failure['confidence']:.2f}")
                print()

async def main():
    """Run the comprehensive test suite"""
    tester = URLClassifierTester()
    
    try:
        print("Starting real URL classification test suite...")
        print("This will test against live websites - may take 1-2 minutes")
        print()
        
        analysis = await tester.run_tests()
        tester.print_results(analysis)
        
        # Save results to file for further analysis
        with open('test_results.json', 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        print("Detailed results saved to test_results.json")
        
    except Exception as e:
        logger.error(f"Test suite failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())