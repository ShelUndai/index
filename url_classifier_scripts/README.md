# URL Classifier Scripts

## Overview

This project provides a robust, production-grade URL classifier for inventory and analytics use cases. It can classify real-world URLs as APIs (REST, GraphQL, etc.), UIs (React, Angular, Vue, Next.js, WordPress, etc.), files (PDF, images, etc.), redirects, and error endpoints. The classifier is designed to handle a wide range of edge cases, including protected APIs, ambiguous content types, timeouts, and more.

## Features
- **Type Detection:** Classifies URLs as API, UI, FILE, REDIRECT, or ERROR.
- **Subtype Detection:** Identifies REST, GraphQL, React, Angular, Vue.js, Next.js, Node.js, and more.
- **Technology Detection:** Detects frontend and backend technologies (React, Angular, Vue, Next.js, WordPress, Node.js, etc.).
- **Edge Case Handling:** Handles redirects, timeouts, protected endpoints, ambiguous file types, and more.
- **Performance:** Uses async HTTP requests with configurable concurrency and timeouts.
- **Caching:** Optional in-memory caching for repeated classifications.
- **Extensible:** Easily add new patterns or domain-based rules.

## Installation

1. **Clone the repository:**
   ```sh
   git clone <your-repo-url>
   cd url_classifier_scripts
   ```
2. **Create and activate a virtual environment:**
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies:**
   ```sh
   pip install httpx pyyaml
   ```

## Usage

### Running the Test Suite
To validate the classifier against real-world URLs and edge cases:
```sh
source venv/bin/activate
python url_classifier_scripts/tests_url_classifier.py
```
- Results and a summary will be printed to the console.
- Detailed results are saved to `test_results.json`.

### Using the Classifier in Code
Import and use the classifier in your own Python scripts:
```python
from url_classifier import EnhancedInventoryURLClassificationManager, ClassificationConfig

config = ClassificationConfig(
    max_concurrent=20,
    timeout=15,
    content_limit_kb=200,
    verbose_logging=True,
    enable_caching=True,
    min_confidence_threshold=0.7
)
manager = EnhancedInventoryURLClassificationManager(config)
# See tests_url_classifier.py for example usage
```

## API Documentation

### Main Classes

#### `ClassificationConfig`
Configuration for the classifier. Key parameters:
- `max_concurrent`: Maximum concurrent HTTP requests.
- `timeout`: Timeout (seconds) for each request.
- `content_limit_kb`: Max content size to fetch (KB).
- `verbose_logging`: Enable detailed logs.
- `enable_caching`: Use in-memory cache.
- `min_confidence_threshold`: Minimum confidence for a result to be considered reliable.

#### `EnhancedInventoryURLClassificationManager`
High-level manager for classifying batches of URLs.
- `__init__(config: ClassificationConfig)`
- `update_inventory_classifications(get_urls_callback, update_callback, progress_callback=None)`
    - `get_urls_callback`: Returns a list of URLs or (id, url) tuples.
    - `update_callback`: Called with (id, classification_result_dict) for each classified URL.
    - `progress_callback`: Optional, called with (current, total, result) for progress updates.

#### `URLClassificationResult`
Result object for a classified URL. Fields:
- `url`: The URL classified
- `classification_type`: 'API', 'UI', 'FILE', 'REDIRECT', or 'ERROR'
- `classification_subtype`: e.g. 'REST', 'GraphQL', 'React', etc.
- `technologies`: List of detected technologies
- `confidence_score`: 0.0–1.0
- `status_code`: HTTP status code
- `error_message`: Error details if any
- `redirect_chain`: List of redirect URLs (if any)

### Key Functions

#### Classifying a Single URL
You can use the lower-level `SmartURLClassifier` for single URL classification:
```python
from url_classifier import ClassificationConfig, SmartURLClassifier
import asyncio

async def classify_one(url):
    config = ClassificationConfig(timeout=10)
    classifier = SmartURLClassifier(config)
    async with classifier:
        result = await classifier._classify_single_url(url)
        print(result)

asyncio.run(classify_one('https://reactjs.org'))
```

#### Batch Classification
See `tests_url_classifier.py` for a full example of batch classification with callbacks.

### Extending the Classifier

#### Adding New Technology or API Patterns
Edit the `EnhancedTechnologyDetector` class in `url_classifier.py`:
```python
# Example: Add a new frontend framework
frontend_raw_patterns = {
    ...
    'MyFramework': [r'myframework\.js', r'MyFramework\.init\('],
}
```

#### Adding Domain-Based Rules
In the `_classify_single_url` logic, add custom rules for specific domains or URL patterns:
```python
if 'mycompany.com' in domain and '/internal-api/' in path:
    final_type = 'API'
    final_subtype = 'Internal'
```

#### Adjusting Configuration
You can tune concurrency, timeouts, and thresholds via `ClassificationConfig`:
```python
config = ClassificationConfig(max_concurrent=50, timeout=20, min_confidence_threshold=0.8)
```

## Test Suite
- The test suite (`tests_url_classifier.py`) covers 22 real-world and edge case URLs.
- It checks type, subtype, and technology detection accuracy, and prints a summary and failures analysis.
- The suite is designed to be extensible—add your own test cases as needed.

## Customization & Extension
- **Add new patterns:** Edit `url_classifier.py` in the `EnhancedTechnologyDetector` class to add new regex patterns for technologies or API types.
- **Domain-based rules:** Add new domain/path rules in the classification logic for custom handling.
- **Configuration:** Adjust concurrency, timeouts, and thresholds via `ClassificationConfig`.

## Contributing & Support
- Contributions, bug reports, and feature requests are welcome!
- For questions or help, open an issue or contact the maintainer.

---

**Author:** Your Name Here
**License:** MIT (or your preferred license) 