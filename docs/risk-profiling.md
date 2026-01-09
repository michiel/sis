# Risk Profiling and Calibration

## Overview

The risk profiling and calibration system provides comprehensive document-level risk assessment with calibrated predictions, category-specific risk breakdowns, and human-readable interpretations.

**Key Features**:
- Calibrated probability predictions with confidence intervals
- 6 category-specific risk profiles (JS, URI, Structural, SupplyChain, Content, Crypto)
- Multiple calibration methods (Platt Scaling, Isotonic Regression)
- Natural language risk interpretations
- Metadata extraction from findings

---

## Core Structures

### DocumentRiskProfile

Comprehensive document-level risk assessment aggregating all signals.

```rust
pub struct DocumentRiskProfile {
    // Calibrated prediction
    pub prediction: CalibratedPrediction,

    // Finding counts
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_severity_count: usize,
    pub medium_severity_count: usize,
    pub low_severity_count: usize,

    // Diversity metrics
    pub attack_surface_diversity: usize,
    pub max_confidence: String,

    // Category-specific profiles
    pub js_risk: JsRiskProfile,
    pub uri_risk: UriRiskProfile,
    pub structural_risk: StructuralRiskProfile,
    pub supply_chain_risk: SupplyChainRiskProfile,
    pub content_risk: ContentRiskProfile,
    pub crypto_risk: CryptoRiskProfile,

    // Comprehensive explanations
    pub explanation: MlExplanation,
    pub comparative_analysis: Vec<ComparativeFeature>,
    pub graph_paths: Option<GraphPathExplanation>,
    pub evidence_chains: Vec<EvidenceChain>,
}
```

### CalibratedPrediction

Prediction with confidence intervals and human-readable interpretation.

```rust
pub struct CalibratedPrediction {
    pub raw_score: f32,              // Raw ML model score
    pub calibrated_score: f32,        // Calibrated probability [0,1]
    pub confidence_interval: (f32, f32), // 95% CI
    pub calibration_method: String,   // "PlattScaling" or "IsotonicRegression"
    pub interpretation: String,       // Human-readable risk level
}
```

**Interpretation Levels**:
- `calibrated_score >= 0.9`: Very high confidence malicious
- `0.7 - 0.9`: Likely malicious
- `0.5 - 0.7`: Possibly malicious
- `0.3 - 0.5`: Unlikely malicious
- `< 0.3`: Very low probability malicious

---

## Calibration Models

### CalibrationModel

Transforms raw ML scores into calibrated probabilities.

```rust
pub struct CalibrationModel {
    pub method: CalibrationMethod,
}

pub enum CalibrationMethod {
    PlattScaling { a: f32, b: f32 },
    IsotonicRegression { x: Vec<f32>, y: Vec<f32> },
}
```

### Platt Scaling

Logistic sigmoid transformation: `σ(ax + b) = 1 / (1 + exp(-ax - b))`

**Usage**:
```rust
let calibrator = CalibrationModel::platt_scaling(1.5, -0.5);
let calibrated = calibrator.calibrate(raw_score);
```

**When to use**:
- Simple, parametric approach
- Works well when raw scores are roughly linear with log-odds
- Requires fewer calibration samples than isotonic regression
- Faster computation

### Isotonic Regression

Non-parametric piecewise constant calibration with linear interpolation.

**Usage**:
```rust
let x = vec![0.0, 0.3, 0.5, 0.7, 1.0]; // Raw score bins
let y = vec![0.05, 0.25, 0.5, 0.8, 0.95]; // Calibrated probabilities
let calibrator = CalibrationModel::isotonic_regression(x, y);
let calibrated = calibrator.calibrate(raw_score);
```

**When to use**:
- Non-parametric, flexible approach
- Handles arbitrary score distributions
- Better for complex calibration curves
- Requires more calibration samples

### Persistence

```rust
// Save calibration model
calibrator.save_to_file(Path::new("calibration.json"))?;

// Load calibration model
let calibrator = CalibrationModel::load_from_file(Path::new("calibration.json"))?;
```

**JSON Format**:
```json
{
  "method": {
    "PlattScaling": {
      "a": 1.5,
      "b": -0.5
    }
  }
}
```

---

## Category-Specific Risk Profiles

### JsRiskProfile

JavaScript-related risks.

```rust
pub struct JsRiskProfile {
    pub present: bool,                // JS detected in document
    pub eval_usage: bool,             // eval/Function constructor used
    pub max_obfuscation: f32,         // Highest obfuscation score [0,1]
    pub multi_stage: bool,            // Multi-stage JS execution
    pub risk_score: f32,              // Category risk [0,1]
}
```

**Extracted from findings**:
- `js_eval`, `js_function_constructor`, `js_obfuscated`
- Metadata: `js.obfuscation_score`, `js.eval_count`, `js.stages`

### UriRiskProfile

URI and external resource risks.

```rust
pub struct UriRiskProfile {
    pub present: bool,
    pub suspicious_domains: usize,    // Count of suspicious domains
    pub suspicious_schemes: usize,    // Non-HTTP schemes
    pub phishing_indicators: usize,   // Phishing signals
    pub risk_score: f32,
}
```

**Extracted from findings**:
- `uri_suspicious_domain`, `uri_ip_address`, `uri_non_standard_port`
- Metadata: `uri.domain`, `uri.scheme`, `uri.is_phishing`

### StructuralRiskProfile

PDF structure violations and anomalies.

```rust
pub struct StructuralRiskProfile {
    pub present: bool,
    pub xref_conflicts: usize,        // Cross-reference issues
    pub spec_violations: usize,       // PDF spec violations
    pub compression_bombs: usize,     // Decompression bombs
    pub risk_score: f32,
}
```

**Extracted from findings**:
- `xref_conflict`, `spec_violation_*`, `compression_bomb`

### SupplyChainRiskProfile

Document provenance and trust.

```rust
pub struct SupplyChainRiskProfile {
    pub present: bool,
    pub untrusted_producers: usize,   // Suspicious producers
    pub missing_signatures: usize,    // Unsigned when expected
    pub invalid_signatures: usize,    // Invalid signatures
    pub risk_score: f32,
}
```

**Extracted from findings**:
- `supply_chain_untrusted_producer`, `supply_chain_missing_signature`
- Metadata: `producer_trust`, `signature_valid`

### ContentRiskProfile

Document content analysis.

```rust
pub struct ContentRiskProfile {
    pub present: bool,
    pub phishing_keywords: usize,     // Phishing indicators
    pub hidden_content: usize,        // Invisible text/objects
    pub suspicious_patterns: usize,   // Anomalous patterns
    pub risk_score: f32,
}
```

**Extracted from findings**:
- `content_phishing_keywords`, `content_hidden_text`
- Metadata: `phishing_score`, `hidden_ratio`

### CryptoRiskProfile

Cryptographic weaknesses.

```rust
pub struct CryptoRiskProfile {
    pub present: bool,
    pub weak_encryption: bool,        // RC4, DES detected
    pub weak_hashing: bool,           // MD5 detected
    pub certificate_issues: usize,    // Certificate problems
    pub risk_score: f32,
}
```

**Extracted from findings**:
- `crypto_weak_encryption`, `crypto_weak_hash`, `crypto_cert_*`
- Metadata: `encryption_algorithm`, `hash_algorithm`

---

## Usage Examples

### Basic Risk Profiling

```rust
use sis_pdf_core::explainability::{
    generate_document_risk_profile,
    CalibrationModel,
    calibrate_prediction,
    MlExplanation,
};

// Get findings from analysis
let findings = analyze_pdf(&pdf_path)?;

// Create calibrated prediction
let raw_score = 0.85; // From ML model
let calibrator = CalibrationModel::load_from_file("calibration.json")?;
let prediction = calibrate_prediction(raw_score, &calibrator);

// Generate ML explanation (from Phase 1)
let explanation = MlExplanation::default(); // Or compute from features

// Generate comparative analysis (from Phase 3)
let comparative = vec![]; // Or compute from baseline

// Generate graph paths (from Phase 3)
let graph_paths = None; // Or extract from ORG

// Generate document risk profile
let risk_profile = generate_document_risk_profile(
    &findings,
    prediction,
    explanation,
    comparative,
    graph_paths,
    vec![], // evidence_chains
);

// Access risk information
println!("Risk: {}", risk_profile.prediction.interpretation);
println!("JS Risk: {:.2}", risk_profile.js_risk.risk_score);
println!("Total findings: {}", risk_profile.total_findings);
```

### Training Calibration Model (Python)

```python
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.isotonic import IsotonicRegression
import json

# Load validation predictions
val_scores = np.load("val_predictions.npy")  # Raw scores
val_labels = np.load("val_labels.npy")        # True labels

# Method 1: Platt Scaling
from sklearn.linear_model import LogisticRegression
lr = LogisticRegression()
lr.fit(val_scores.reshape(-1, 1), val_labels)
a, b = lr.coef_[0][0], lr.intercept_[0]

platt_model = {
    "method": {
        "PlattScaling": {"a": float(a), "b": float(b)}
    }
}
with open("calibration_platt.json", "w") as f:
    json.dump(platt_model, f, indent=2)

# Method 2: Isotonic Regression
iso = IsotonicRegression(out_of_bounds="clip")
calibrated_scores = iso.fit_transform(val_scores, val_labels)

# Create bins for piecewise function
bins = np.linspace(0, 1, 11)  # 10 bins
x_bins = []
y_bins = []
for i in range(len(bins)):
    bin_val = bins[i]
    x_bins.append(float(bin_val))
    y_bins.append(float(iso.predict([bin_val])[0]))

iso_model = {
    "method": {
        "IsotonicRegression": {"x": x_bins, "y": y_bins}
    }
}
with open("calibration_isotonic.json", "w") as f:
    json.dump(iso_model, f, indent=2)
```

### Calibration Evaluation

```python
from sklearn.metrics import brier_score_loss, log_loss

# Uncalibrated scores
brier_uncal = brier_score_loss(val_labels, val_scores)
logloss_uncal = log_loss(val_labels, val_scores)

# Calibrated scores (Platt)
platt_scores = 1 / (1 + np.exp(-a * val_scores - b))
brier_platt = brier_score_loss(val_labels, platt_scores)
logloss_platt = log_loss(val_labels, platt_scores)

# Calibrated scores (Isotonic)
iso_scores = iso.predict(val_scores)
brier_iso = brier_score_loss(val_labels, iso_scores)
logloss_iso = log_loss(val_labels, iso_scores)

print(f"Uncalibrated - Brier: {brier_uncal:.4f}, LogLoss: {logloss_uncal:.4f}")
print(f"Platt        - Brier: {brier_platt:.4f}, LogLoss: {logloss_platt:.4f}")
print(f"Isotonic     - Brier: {brier_iso:.4f}, LogLoss: {logloss_iso:.4f}")
```

### Category Risk Analysis

```rust
// Analyze category-specific risks
let profile = generate_document_risk_profile(/* ... */);

// JavaScript risks
if profile.js_risk.present {
    println!("JavaScript Risk: {:.2}", profile.js_risk.risk_score);
    if profile.js_risk.eval_usage {
        println!("  - Uses eval or Function constructor");
    }
    if profile.js_risk.max_obfuscation > 0.7 {
        println!("  - High obfuscation: {:.2}", profile.js_risk.max_obfuscation);
    }
}

// URI risks
if profile.uri_risk.present {
    println!("URI Risk: {:.2}", profile.uri_risk.risk_score);
    println!("  - Suspicious domains: {}", profile.uri_risk.suspicious_domains);
    println!("  - Phishing indicators: {}", profile.uri_risk.phishing_indicators);
}

// Structural risks
if profile.structural_risk.present {
    println!("Structural Risk: {:.2}", profile.structural_risk.risk_score);
    println!("  - Xref conflicts: {}", profile.structural_risk.xref_conflicts);
    println!("  - Spec violations: {}", profile.structural_risk.spec_violations);
}

// Overall assessment
println!("\nOverall Assessment:");
println!("{}", profile.prediction.interpretation);
```

---

## Integration with ML Pipeline

### Feature Extraction → Inference → Risk Profiling

```rust
// 1. Extract extended features (Phase 1)
let feature_vector = extract_extended_feature_vector(&findings);

// 2. Run ML inference
let raw_score = ml_model.predict(&feature_vector)?;

// 3. Calibrate prediction
let calibrator = CalibrationModel::load_from_file("calibration.json")?;
let prediction = calibrate_prediction(raw_score, &calibrator);

// 4. Generate explanations (Phase 1)
let baseline = BenignBaseline::load_from_file("baseline.json")?;
let explanation = create_ml_explanation(&feature_vector, raw_score, &baseline)?;

// 5. Compute comparative analysis (Phase 3)
let comparative = compute_comparative_explanation(&feature_vector, &baseline);

// 6. Extract graph paths (Phase 3)
let graph_paths = extract_suspicious_paths(&action_chains, &findings);

// 7. Generate comprehensive risk profile
let risk_profile = generate_document_risk_profile(
    &findings,
    prediction,
    explanation,
    comparative,
    Some(graph_paths),
    vec![],
);

// 8. Export as JSON
let json = serde_json::to_string_pretty(&risk_profile)?;
std::fs::write("risk_profile.json", json)?;
```

---

## Best Practices

### Calibration Model Selection

**Use Platt Scaling when**:
- You have 100-1000 calibration samples
- Raw scores are roughly well-calibrated already
- You need fast inference
- You want a simple, interpretable model

**Use Isotonic Regression when**:
- You have 1000+ calibration samples
- Raw scores have non-linear relationship with true probabilities
- Calibration accuracy is critical
- Slightly slower inference is acceptable

### Category Risk Scoring

Each category risk score is computed as:
```rust
risk_score = min(1.0, 0.3 * presence + 0.7 * severity_factor)

where:
  presence = 1.0 if any findings in category, else 0.0
  severity_factor = weighted average of finding severities
```

### Confidence Interval Estimation

CI width is estimated based on calibrated score:
```rust
ci_width = 0.1 * (1 - p) * p * 4
where p = calibrated_score

// Binomial variance maximized at p=0.5, scaled to ±10%
```

For production use, consider:
- Bootstrap resampling for empirical CIs
- Conformal prediction for guaranteed coverage
- Model uncertainty estimation (e.g., ensemble variance)

---

## API Reference

### Functions

#### `generate_document_risk_profile`

```rust
pub fn generate_document_risk_profile(
    findings: &[Finding],
    prediction: CalibratedPrediction,
    explanation: MlExplanation,
    comparative_analysis: Vec<ComparativeFeature>,
    graph_paths: Option<GraphPathExplanation>,
    evidence_chains: Vec<EvidenceChain>,
) -> DocumentRiskProfile
```

Generates comprehensive document-level risk profile.

#### `calibrate_prediction`

```rust
pub fn calibrate_prediction(
    raw_score: f32,
    calibrator: &CalibrationModel,
) -> CalibratedPrediction
```

Calibrates raw ML score and generates interpretation.

#### `CalibrationModel::calibrate`

```rust
pub fn calibrate(&self, raw_score: f32) -> f32
```

Transforms raw score to calibrated probability.

#### `CalibrationModel::load_from_file`

```rust
pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn Error>>
```

Loads calibration model from JSON file.

#### `CalibrationModel::save_to_file`

```rust
pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn Error>>
```

Saves calibration model to JSON file.

---

## Testing

All functionality is covered by comprehensive tests in `crates/sis-pdf-core/src/explainability.rs`:

- `test_platt_scaling_calibration` - Sigmoid behavior
- `test_isotonic_regression_calibration` - Interpolation
- `test_calibrate_prediction` - End-to-end calibration
- `test_calibration_model_save_load` - Persistence
- `test_js_risk_profile_extraction` - JS metadata parsing
- `test_uri_risk_profile_extraction` - URI analysis
- `test_structural_risk_profile_extraction` - Structure issues
- `test_generate_document_risk_profile` - Full integration
- `test_category_risk_profiles_default` - Default values
- `test_calibrated_prediction_interpretation` - Human-readable text
- `test_confidence_interval_computation` - CI estimation

Run tests:
```bash
cargo test --package sis-pdf-core --lib explainability
```

---

## See Also

- [ML Signals Plan](../NEXT_STEPS.md)
- [Feature Extraction](explainability.md)
- [Enhanced IR and ORG](ir-org-graph.md)
- [Finding Specifications](findings.md)
