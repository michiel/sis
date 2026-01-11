# Implementation Plan: Detection Updates from 2022/2024 Corpus Analysis

**Date**: 2026-01-11
**Status**: Planning
**Priority**: Critical
**Dependencies**: Corpus analysis complete (2022 benign/malicious, 2024 malicious)

---

## Executive Summary

This plan implements improvements to SIS PDF's detection capabilities based on comprehensive corpus analysis of:
- **30,949 PDFs from 2022** (21,842 malicious, 9,107 benign)
- **287,777 PDFs from 2024** (VirusShare malicious)
- **6.5 million findings** with 72 unique detection types

### Critical Findings Requiring Action

1. **Model Obsolescence**: 2022-trained models will have 60-70% false negative rate on 2024 samples
2. **Attack Vector Shift**: JavaScript exploitation (81.7% → 22.8%) to social engineering/phishing (URIs 1.4% → 47.8%)
3. **Evasion Sophistication**: 2024 malware mimics benign patterns (incremental updates, proper structure)
4. **Detection Gaps**: Traditional indicators (missing EOF, open actions) decreased 6-17x in effectiveness

### Three-Track Implementation

1. **Track 1: ML Model Training** (2-3 weeks) - Retrain models with 2024 corpus, new features
2. **Track 2: Detection Rule Updates** (1 week) - Deploy updated YARA/heuristic rules
3. **Track 3: Threat Intelligence** (1 week) - Generate reports, update IOC feeds

---

## Strategic Recommendations

### Immediate Actions (Week 1)

1. **Deploy 2024-Aware Rules First**
   - **Why**: Rule-based detection can be deployed immediately without ML training
   - **Impact**: Closes 40-50% of detection gap on 2024 samples
   - **Effort**: 2-3 days for YARA rules + heuristic updates
   - **ROI**: High - Quick wins with minimal investment

2. **Start ML Training in Parallel**
   - **Why**: Models take 2-3 weeks but provide highest accuracy
   - **Impact**: Addresses remaining 50-60% detection gap
   - **Effort**: 3-4 weeks for full pipeline
   - **ROI**: Very High - Sustainable long-term solution

3. **Collect 2024 Benign Corpus**
   - **Why**: Critical for false positive validation
   - **Sources**:
     - Corporate document repositories (with permission)
     - Public datasets (govdocs1, arxiv PDFs)
     - PDF/A archives (long-term preservation)
   - **Target**: 5-10K modern PDFs
   - **Timeline**: Start immediately, complete within 2 weeks

### Prioritization Framework

**Tier 1 (Critical - Do First):**
1. Deploy URI analysis heuristics (Track 2, Phase 2.2)
   - Addresses biggest 2024 threat (47.8% prevalence)
   - Low complexity, high impact
   - Can be done in 2 days

2. Update YARA rules for phishing patterns (Track 2, Phase 2.1)
   - Catches credential harvesting (29.5% prevalence)
   - Existing rule infrastructure, just add new patterns
   - 2-3 days

3. Generate IOC feeds (Track 3, Phase 3.2)
   - Enables network-level blocking
   - Hashes already available (287K samples)
   - 1-2 days for automation

**Tier 2 (Important - Do Second):**
1. Train XGBoost classifier (Track 1, Phase 1.3)
   - Highest accuracy potential
   - 5-7 days with feature engineering
   - Foundation for all ML-based detection

2. Publish threat intelligence report (Track 3, Phase 3.1)
   - Educates security teams
   - Justifies detection investment
   - 2-3 days

3. Form field analysis heuristics (Track 2, Phase 2.2)
   - Targets credential harvesting
   - Moderate complexity
   - 2-3 days

**Tier 3 (Nice to Have - Do Third):**
1. Ensemble models (Track 1, Phase 1.3)
   - Marginal accuracy improvement
   - Only if XGBoost < 90% accuracy
   - 3-4 days

2. Temporal validation (Track 2, Phase 2.2)
   - Catches sophisticated evasion
   - Lower prevalence impact
   - 2-3 days

3. Signature generation (Track 3, Phase 3.3)
   - Useful for perimeter defense
   - Limited to known samples
   - 1 day

### Architecture Recommendations

**1. Two-Tier Detection Pipeline**

```
Tier 1: Fast Rules (< 1ms overhead)
├─ YARA signatures (known patterns)
├─ Heuristic checks (URI count, missing signature)
└─ Verdict: CLEAN | SUSPICIOUS | MALICIOUS

If SUSPICIOUS:
Tier 2: ML Classification (5-15ms overhead)
├─ Feature extraction from findings
├─ XGBoost inference
├─ SHAP explanation
└─ Verdict: MALICIOUS (score, confidence, reasoning)
```

**Benefits:**
- Fast path for obvious cases (90% of files)
- Deep analysis only when needed (10% suspicious)
- Explainable results (SHAP values)
- Graceful degradation (rules work if ML unavailable)

**2. Confidence-Based Thresholding**

Instead of binary classification, use three confidence levels:

```
Score > 0.85: HIGH confidence malicious
  → Automatic quarantine
  → Alert SOC immediately
  → Add to IOC feeds

Score 0.50-0.85: MEDIUM confidence suspicious
  → Flag for manual review
  → Lower priority alert
  → Collect for retraining

Score < 0.50: LOW confidence benign
  → Allow with monitoring
  → Log for audit
  → Sample for benign corpus

Score < 0.20: HIGH confidence benign
  → Fast-path allow
  → No logging needed
  → Skip further analysis
```

**Benefits:**
- Reduces analyst workload (focus on medium confidence)
- Lower false positive impact (high threshold for auto-action)
- Continuous learning (collect edge cases for retraining)

**3. Feature Store Architecture**

Don't recompute features on every prediction:

```
PDF File → SIS Scan → Findings JSONL → Feature Cache
                                            ↓
                                       {cached features}
                                            ↓
Rule Engine ← Features     ML Model ← Features
     ↓                          ↓
  Verdict              Score + Explanation
```

**Benefits:**
- Feature extraction once (most expensive operation)
- Share features between rules and ML
- Enable real-time updates (cache invalidation)
- Support multiple models (A/B testing)

### Technology Recommendations

**1. Model Serving**

**Option A: Embedded ONNX (Recommended)**
- Pros: No network overhead, offline capable, fast (5ms)
- Cons: Model updates require binary rebuild
- Use case: CLI tool, edge deployment

**Option B: Model Server (Optional)**
- Pros: Hot model updates, A/B testing, monitoring
- Cons: Network latency, infrastructure overhead
- Use case: High-volume deployment (>10K files/day)

**Recommendation**: Start with embedded ONNX (Option A), add server (Option B) if needed for scale.

**2. Feature Engineering**

**Use existing extraction:**
- 60 finding types already detected
- URI content in evidence fields
- Form fields in metadata
- Don't build parallel extraction

**Add lightweight parsers for:**
- Domain extraction from URIs (regex)
- Form field name extraction (existing in metadata)
- Timestamp parsing (PDF metadata)

**Avoid:**
- Full content extraction (slow, high complexity)
- External API calls during inference (reliability, latency)
- Deep JavaScript AST parsing (already done in sandbox)

**3. Production Deployment**

**Phase 1: Shadow Mode (Week 1-2)**
- Run new rules alongside existing detection
- Log predictions without taking action
- Compare results, measure false positives
- Goal: Validate performance on live traffic

**Phase 2: Opt-In Mode (Week 3-4)**
- Allow users to enable new detection
- Collect feedback on classifications
- Iterate on thresholds and rules
- Goal: Build confidence, fix edge cases

**Phase 3: Default Enable (Week 5+)**
- Enable for all users by default
- Monitor false positive reports
- Provide override mechanism
- Goal: Full production deployment

### Data Strategy Recommendations

**1. Continuous Corpus Updates**

Don't wait for the next big scan:

```
Monthly:
  - Collect 100-500 new malicious samples (VirusShare, MalwareBazaar)
  - Collect 100-500 new benign samples (trusted sources)
  - Run fast+deep scan
  - Add to training data

Quarterly:
  - Retrain models with cumulative data
  - Evaluate for performance drift
  - Update detection rules
  - Publish threat report

Annually:
  - Full corpus refresh (200K+ samples)
  - Major model architecture updates
  - Comprehensive evaluation
  - Update all documentation
```

**2. Benign Corpus Collection Strategy**

**High-Priority Sources:**
```
1. GovDocs1 (IRS forms, government documents)
   - 2M+ PDFs from .gov sites
   - Known clean, publicly available
   - Download: https://digitalcorpora.org/corpora/files

2. ArXiv Research Papers
   - 2M+ scientific PDFs
   - LaTeX-generated (consistent structure)
   - API available for bulk download

3. PDF/A Validation Corpus
   - Long-term preservation PDFs
   - Guaranteed compliant structure
   - Small but high-quality (5-10K samples)

4. Corporate Documents (if available)
   - Internal reports, presentations
   - Real-world usage patterns
   - Requires data usage agreement
```

**Target Distribution:**
```
Total: 10,000 benign PDFs (2024)
├─ GovDocs1: 4,000 (government)
├─ ArXiv: 3,000 (academic)
├─ PDF/A: 2,000 (archival)
└─ Corporate: 1,000 (business)
```

**3. Active Learning Strategy**

Use model predictions to guide corpus expansion:

```
1. Run classifier on large unlabeled corpus
2. Select samples near decision boundary (score 0.45-0.55)
3. Manually label high-uncertainty samples
4. Add to training set
5. Retrain model
6. Repeat quarterly

Result:
  - 10-20% accuracy improvement
  - Focus labeling effort on hard cases
  - Discover new attack variants
```

### Cost-Benefit Analysis

**Investment:**
- Engineering time: 4 weeks (1-2 FTEs)
- Compute resources: ~$100 (cloud GPU for training)
- Ongoing: 1 day/month maintenance

**Returns:**
- Detection rate improvement: 60-70% on 2024 samples
- False negative reduction: ~$50K-500K per incident prevented
- Analyst time savings: 20-30% (better triage)
- Threat intelligence value: Industry-leading insights

**Break-even:** First prevented incident (ROI: 500-5000x)

### Collaboration Recommendations

**1. Open Source Contributions**

Consider open-sourcing (after internal review):
- Temporal trend analysis (industry benefit)
- Feature engineering code (research value)
- Evaluation methodology (reproducibility)

**Benefits:**
- Community contributions (new features, bug fixes)
- Academic citations (research credibility)
- Industry recognition (thought leadership)

**Keep proprietary:**
- Trained model weights (competitive advantage)
- Specific YARA rules (detection evasion risk)
- IOC feeds (operational security)

**2. Threat Intelligence Sharing**

Join information sharing communities:
- **FIRST** (Forum of Incident Response and Security Teams)
- **ISAC** (Information Sharing and Analysis Centers)
- **MISP** (Malware Information Sharing Platform)

Share:
- Aggregate statistics (trends, prevalence)
- Attack pattern TTPs (MITRE ATT&CK mapping)
- Anonymized IOCs (hashes, patterns)

Receive:
- Early warning of new campaigns
- Coordinated response to threats
- Validation of detection efficacy

**3. Vendor Partnerships**

Potential integrations:
- **VirusTotal**: Submit findings, validate against 70+ engines
- **URLhaus**: Domain reputation for URI analysis
- **PhishTank**: Phishing URL database integration
- **Hybrid Analysis**: Automated sandbox integration

### Future Research Directions

**1. Explainable AI (XAI)**

Current plan includes SHAP values, but consider:
- Natural language explanations ("This PDF is malicious because...")
- Visual highlighting (mark suspicious objects in PDF)
- Counterfactual examples ("If it had a signature, it would be benign")

**2. Adversarial Robustness**

Test models against evasion:
- Add benign features to malicious samples (can we still detect?)
- Remove malicious features incrementally (what's the threshold?)
- Generate adversarial examples (find model blind spots)

**3. Zero-Day Detection**

Look beyond known patterns:
- Anomaly detection (what's unusual for benign or malicious?)
- Generative models (what would a new attack look like?)
- Transfer learning (apply knowledge from other file formats)

**4. Content-Based Analysis**

Current analysis is structure-focused, add:
- Text extraction + NLP (phishing language detection)
- OCR for images (hidden text, overlays)
- Font analysis (embedded exploits in font tables)

### Measurement & Success Metrics

**Detection Efficacy:**
```
Primary Metrics:
  - True Positive Rate (Recall): Target >85% on 2024 malicious
  - False Positive Rate: Target <10% on 2024 benign
  - AUC-ROC: Target >0.90
  - F1-Score: Target >0.85

Secondary Metrics:
  - Precision at High Confidence (>0.85): Target >95%
  - Coverage of Attack Vectors: Target >80% of known TTPs
  - Time to Detection: Target <100ms per file
```

**Operational Impact:**
```
Analyst Efficiency:
  - Triage time reduction: Target 30% faster
  - False positive investigation: Target 50% reduction
  - Escalation accuracy: Target 90% of escalations are TP

System Performance:
  - Throughput: Maintain >2,000 files/s
  - Latency P95: <50ms per classification
  - Resource usage: <10% CPU overhead
```

**Business Value:**
```
Risk Reduction:
  - Incidents prevented: Track monthly
  - Mean Time to Detect (MTTD): Target <1 hour
  - Mean Time to Respond (MTTR): Target <4 hours

Cost Savings:
  - Analyst hours saved: Calculate monthly
  - Incident response costs avoided: Estimate per incident
  - Compliance audit value: Track coverage improvements
```

### Risk Mitigation Strategies

**Technical Risks:**

1. **Model performance degradation over time**
   - Mitigation: Quarterly retraining, performance monitoring
   - Contingency: Rollback to previous model version
   - Alert threshold: AUC drops below 0.85

2. **Feature extraction bugs**
   - Mitigation: Comprehensive unit tests, validation on known samples
   - Contingency: Graceful degradation to rule-based detection
   - Detection: Automated testing in CI/CD

3. **Inference latency spikes**
   - Mitigation: Performance benchmarks, load testing
   - Contingency: Async processing queue for high-volume
   - Alert threshold: P95 latency >100ms

**Operational Risks:**

1. **High false positive rate**
   - Mitigation: Shadow mode deployment, conservative thresholds
   - Contingency: User feedback mechanism, rapid threshold adjustment
   - Alert threshold: FP rate >15% in production

2. **Analyst training gap**
   - Mitigation: Comprehensive documentation, hands-on workshops
   - Contingency: Extended shadow mode, gradual rollout
   - Success metric: 90% analyst confidence in new system

3. **Integration challenges**
   - Mitigation: Multiple deployment options (CLI, API, embedded)
   - Contingency: Standalone mode with file exports
   - Validation: End-to-end testing before release

### Knowledge Transfer Plan

**Documentation:**
- [ ] Model architecture whitepaper (10-15 pages)
- [ ] Feature engineering guide (code comments + examples)
- [ ] Deployment runbook (step-by-step)
- [ ] Troubleshooting guide (common issues + solutions)

**Training:**
- [ ] Analyst workshop (2 hours): How to interpret classifications
- [ ] Engineering deep-dive (4 hours): Model internals, maintenance
- [ ] Executive briefing (30 min): Business value, ROI

**Ongoing Support:**
- [ ] Weekly office hours (first month)
- [ ] Slack/Teams channel for questions
- [ ] Monthly review of performance metrics
- [ ] Quarterly model update sessions

---

## Track 1: ML Model Training

### Objective

Build temporally-aware classification models that maintain high accuracy across 2022 and 2024 threat landscapes.

### Current State Assessment

**Existing model weaknesses (trained on 2022):**
- JavaScript-focused features over-weighted (81.7% → 22.8% prevalence)
- Missing URI/link analysis (1.4% → 47.8% prevalence)
- No temporal validation (incremental updates not analyzed)
- No form field analysis (credential harvesting detection)
- Binary classification (no confidence scores)

### Dataset Preparation

#### Phase 1.1: Corpus Organization (2 days)

**Inputs:**
- `malicious_2022_scan.jsonl` (125,716 findings, 21,842 files)
- `malicious_2022_deep_scan.jsonl` (150,362 findings, 21,842 files)
- `benign_2022_scan.jsonl` (152,353 findings, 8,604 files)
- `benign_2022_deep_scan.jsonl` (183,142 findings, 8,616 files)
- `virusshare_2024_scan.jsonl` (6,141,196 findings, 287,754 files)
- `virusshare_2024_deep_scan.jsonl` (6,240,071 findings, 287,777 files)

**Tasks:**
1. **Extract feature vectors from JSONL findings**
   ```python
   # scripts/extract_ml_features.py
   # Per-file feature vector:
   {
     "file_path": "...",
     "label": "malicious|benign",
     "corpus": "2022_mal|2022_ben|2024_mal",
     "features": {
       # Structural (52 types)
       "js_present": 0|1,
       "js_sandbox_exec": 0|1,
       "uri_present": 0|1,
       "incremental_update_chain": 0|1,
       # ... all finding kinds as binary features

       # Quantitative
       "finding_count_total": int,
       "finding_count_high_severity": int,
       "finding_count_medium_severity": int,
       "uri_count": int,
       "js_function_count": int,
       "incremental_update_count": int,
       "object_shadowing_count": int,

       # Combination features
       "js_and_uri": 0|1,
       "uri_without_signature": 0|1,
       "incremental_without_signature": 0|1,
       "acroform_and_js": 0|1,
       "annotation_chain_and_uri": 0|1,

       # Temporal (if available)
       "has_timestamps": 0|1,
       "creation_to_modification_days": float|null,
     }
   }
   ```

2. **Create stratified train/val/test splits**
   ```
   2022 Malicious:
     - Train: 15,489 (70%)
     - Val:    3,276 (15%)
     - Test:   3,277 (15%)

   2022 Benign:
     - Train: 6,022 (70%)
     - Val:   1,291 (15%)
     - Test:  1,291 (15%)

   2024 Malicious (temporal validation):
     - Train: 201,444 (70%)
     - Val:    43,167 (15%)
     - Test:   43,166 (15%)

   Total: 314,423 samples
   ```

3. **Balance dataset options**
   - **Option A**: Oversample benign (weight 2022 benign 13x)
   - **Option B**: Undersample 2024 malicious (random 30K subset)
   - **Option C**: Class weights (inverse frequency)
   - **Recommended**: Option C + stratified sampling

4. **Generate metadata files**
   ```
   ml_data/
     train_2022_mal.jsonl
     train_2022_ben.jsonl
     train_2024_mal.jsonl
     val_2022_mal.jsonl
     val_2022_ben.jsonl
     val_2024_mal.jsonl
     test_2022_mal.jsonl
     test_2022_ben.jsonl
     test_2024_mal.jsonl
     metadata.json (split statistics, feature counts)
   ```

**Deliverables:**
- [ ] `scripts/extract_ml_features.py` - Feature extraction script
- [ ] `scripts/create_ml_splits.py` - Train/val/test splitting
- [ ] `ml_data/` directory with split datasets
- [ ] Feature engineering documentation

#### Phase 1.2: Feature Engineering (3 days)

**New features for 2024 threat landscape:**

1. **URI Analysis Features**
   ```python
   # Extract from uri_present findings
   "uri_count": int,                    # Total URIs in document
   "uri_unique_domains": int,           # Unique external domains
   "uri_suspicious_tld": 0|1,          # .tk, .ml, .ga, etc.
   "uri_ip_address": 0|1,              # IP instead of domain
   "uri_obfuscated": 0|1,              # Encoded URLs
   "uri_mismatch_text": 0|1,           # Display text ≠ actual URL
   "uri_newly_registered": 0|1,        # Domain age < 30 days (if available)
   "uri_external_count": int,          # Non-document URIs
   ```

2. **Form Analysis Features**
   ```python
   # Extract from acroform_present findings
   "form_field_count": int,
   "form_has_submit_action": 0|1,
   "form_submit_external": 0|1,
   "form_credential_fields": 0|1,      # Password/SSN fields
   "form_with_js": 0|1,                # Form + JavaScript combo
   "form_field_obfuscated": 0|1,       # Suspicious field names
   ```

3. **Temporal/Structural Features**
   ```python
   # Extract from incremental_update_chain findings
   "incremental_count": int,
   "incremental_rapid": 0|1,           # >5 updates in <1 hour
   "object_shadowing_ratio": float,    # Shadowed / total objects
   "xref_conflict_count": int,
   ```

4. **JavaScript Behavioral Features**
   ```python
   # Extract from js_runtime_* findings
   "js_risky_calls": 0|1,
   "js_network_intent": 0|1,
   "js_file_probe": 0|1,
   "js_polymorphic": 0|1,
   "js_obfuscation_layers": int,
   "js_sandbox_timeout": 0|1,
   ```

5. **Legitimacy Indicators (Negative Features)**
   ```python
   # Benign signals
   "signature_present": 0|1,           # Strong benign (-1.0 weight)
   "encryption_present": 0|1,          # Corporate security
   "linearization_valid": 0|1,         # Web optimization
   "signature_and_incremental": 0|1,   # Multi-author signed doc
   ```

6. **Combination/Interaction Features**
   ```python
   # High-value combinations
   "uri_acroform_js": 0|1,             # Phishing combo
   "uri_embedded_no_sig": 0|1,         # Payload delivery
   "incremental_shadowing_high": 0|1,  # Manipulation
   "js_risky_and_uri": 0|1,            # Exploit + exfiltration
   ```

**Feature selection:**
- Total features: ~150-200
- Correlation analysis to remove redundant features
- Feature importance ranking (Random Forest)
- Keep top 50-80 features for production models

**Deliverables:**
- [ ] Feature engineering code with URI/form extraction
- [ ] Feature correlation matrix visualization
- [ ] Feature importance rankings
- [ ] Documentation of feature definitions

#### Phase 1.3: Model Training (5 days)

**Multi-model ensemble approach:**

1. **Model 1: Gradient Boosting (XGBoost)**
   ```python
   # Primary classifier
   import xgboost as xgb

   params = {
       'max_depth': 8,
       'eta': 0.1,
       'objective': 'binary:logistic',
       'eval_metric': 'auc',
       'scale_pos_weight': 1.0,  # Adjust for class imbalance
       'tree_method': 'hist',
       'subsample': 0.8,
       'colsample_bytree': 0.8,
   }

   # Train with early stopping on validation AUC
   # Expected performance:
   #   2022 test set: AUC > 0.95, Recall > 90%, Precision > 95%
   #   2024 test set: AUC > 0.90, Recall > 85%, Precision > 90%
   ```

2. **Model 2: Random Forest**
   ```python
   # Ensemble diversity
   from sklearn.ensemble import RandomForestClassifier

   rf = RandomForestClassifier(
       n_estimators=500,
       max_depth=12,
       min_samples_split=20,
       class_weight='balanced',
       n_jobs=-1
   )

   # Provides feature importance for explainability
   ```

3. **Model 3: Neural Network (Optional)**
   ```python
   # Deep learning for complex patterns
   import tensorflow as tf

   model = tf.keras.Sequential([
       tf.keras.layers.Dense(256, activation='relu'),
       tf.keras.layers.Dropout(0.3),
       tf.keras.layers.Dense(128, activation='relu'),
       tf.keras.layers.Dropout(0.3),
       tf.keras.layers.Dense(64, activation='relu'),
       tf.keras.layers.Dense(1, activation='sigmoid')
   ])

   # Train with 2022+2024 combined
   # May capture temporal patterns better
   ```

4. **Model 4: Temporal Classifier**
   ```python
   # Year-specific models
   model_2022 = xgb.train(params, dtrain_2022)
   model_2024 = xgb.train(params, dtrain_2024)

   # Ensemble with year detection:
   if predicted_year == 2022:
       score = model_2022.predict(features)
   else:
       score = model_2024.predict(features)
   ```

**Training strategy:**
- Cross-validation on 2022 data (5-fold)
- Temporal validation on 2024 data (no data leakage)
- Hyperparameter tuning with Optuna (50-100 trials)
- Threshold optimization for different deployment scenarios

**Deliverables:**
- [ ] Trained models (XGBoost, Random Forest, NN)
- [ ] Model performance reports (AUC, precision, recall, F1)
- [ ] Confusion matrices for all test sets
- [ ] Threshold recommendations (high-precision, balanced, high-recall)

#### Phase 1.4: Evaluation & Validation (3 days)

**Evaluation metrics:**

1. **Overall Performance**
   ```
   Metric                2022 Test    2024 Test    Target
   -------------------------------------------------------------
   AUC-ROC              > 0.95       > 0.90       > 0.90
   Precision (0.5 thr)  > 95%        > 90%        > 90%
   Recall (0.5 thr)     > 90%        > 85%        > 85%
   F1-Score             > 0.92       > 0.87       > 0.85
   False Positive Rate  < 5%         < 10%        < 10%
   False Negative Rate  < 10%        < 15%        < 15%
   ```

2. **Temporal Robustness**
   ```
   2022 Malicious → 2024 Malicious:
     - Model trained on 2022 only: Recall ~30-40% (baseline)
     - Model trained on 2024 only: Recall ~85-90% (expected)
     - Model trained on combined:   Recall ~80-85% (target)

   2022 Benign → 2024 Benign (when available):
     - False positive rate should remain < 10%
   ```

3. **Feature Analysis**
   ```python
   # Top 20 most important features
   # Compare to 2022 baseline:

   2022 Model Top Features:
   1. js_present (0.15)
   2. js_sandbox_exec (0.12)
   3. open_action_present (0.10)
   4. missing_eof_marker (0.08)
   ...

   2024 Model Top Features (expected):
   1. uri_present (0.12)
   2. uri_acroform_js (0.10)
   3. annotation_action_chain (0.09)
   4. js_present (0.08)  # Still relevant but lower
   5. signature_present (negative, -0.07)
   ...
   ```

4. **Error Analysis**
   ```python
   # False Positives (benign → malicious):
   # - Analyze common patterns in FP
   # - Check if legitimate URIs causing issues
   # - Validate signature checking

   # False Negatives (malicious → benign):
   # - Identify evasion techniques not captured
   # - Check for new attack patterns
   # - Analyze feature coverage
   ```

5. **Explainability**
   ```python
   # SHAP values for model interpretation
   import shap

   explainer = shap.TreeExplainer(xgb_model)
   shap_values = explainer.shap_values(X_test)

   # Generate:
   # - Per-prediction explanations
   # - Global feature importance
   # - Feature interaction plots
   ```

**Deliverables:**
- [ ] Evaluation report with all metrics
- [ ] Error analysis document (FP/FN cases)
- [ ] Feature importance comparison (2022 vs 2024)
- [ ] SHAP explainability visualizations
- [ ] Model selection recommendation

#### Phase 1.5: Model Deployment Preparation (2 days)

**Deployment artifacts:**

1. **Model Export**
   ```python
   # Save models in multiple formats

   # XGBoost native format
   xgb_model.save_model('models/pdf_classifier_2024_xgb.json')

   # ONNX for cross-platform
   import onnxmltools
   onnx_model = onnxmltools.convert_xgboost(xgb_model)
   with open('models/pdf_classifier_2024.onnx', 'wb') as f:
       f.write(onnx_model.SerializeToString())

   # Pickle for Python deployment
   import pickle
   with open('models/pdf_classifier_2024.pkl', 'wb') as f:
       pickle.dump({
           'model': xgb_model,
           'feature_names': feature_names,
           'threshold': optimal_threshold,
           'version': '2024.1'
       }, f)
   ```

2. **Feature Extraction Pipeline**
   ```rust
   // Rust integration for SIS PDF
   // crates/sis-ml/src/feature_extractor.rs

   pub struct FeatureExtractor {
       feature_names: Vec<String>,
   }

   impl FeatureExtractor {
       pub fn extract_from_findings(
           &self,
           findings: &[Finding]
       ) -> Vec<f32> {
           // Convert JSONL findings to feature vector
           // Same logic as Python training code
       }
   }
   ```

3. **Inference API**
   ```rust
   // crates/sis-ml/src/classifier.rs

   pub struct PDFClassifier {
       model: OnnxModel,
       threshold: f32,
   }

   pub struct ClassificationResult {
       pub label: String,  // "malicious" | "benign"
       pub score: f32,     // 0.0 - 1.0
       pub confidence: String,  // "low" | "medium" | "high"
       pub explanation: Vec<(String, f32)>,  // Top features
   }

   impl PDFClassifier {
       pub fn classify(
           &self,
           findings: &[Finding]
       ) -> ClassificationResult {
           let features = extract_features(findings);
           let score = self.model.predict(features);

           ClassificationResult {
               label: if score > self.threshold { "malicious" } else { "benign" },
               score,
               confidence: self.compute_confidence(score),
               explanation: self.top_features(features),
           }
       }
   }
   ```

4. **CLI Integration**
   ```bash
   # New command: sis classify
   ./sis classify document.pdf

   # Output:
   # Classification: MALICIOUS (score: 0.87, confidence: HIGH)
   # Reason: URI-based phishing attack (35% contribution)
   #   - 15 external URIs without digital signature
   #   - AcroForm with credential fields
   #   - JavaScript with network intent
   # Evidence:
   #   - uri_present: +0.31
   #   - uri_acroform_js: +0.28
   #   - signature_present: -0.00 (missing, expected for benign)
   ```

**Performance requirements:**
- Feature extraction: < 10ms per file
- Model inference: < 5ms per file
- Total overhead: < 15ms (acceptable for 2,688 files/s throughput)

**Deliverables:**
- [ ] Exported models (ONNX, JSON, pickle)
- [ ] Rust feature extractor implementation
- [ ] Rust classifier integration
- [ ] CLI `classify` command
- [ ] Deployment documentation

---

## Track 2: Detection Rule Updates

### Objective

Update YARA rules and heuristic detection logic to reflect 2024 threat landscape.

### Current State

**Existing rules (2022 baseline):**
- Heavy JavaScript focus (81.7% prevalence)
- EOF marker validation (58.6% malicious missing EOF)
- Open action detection (71.6% prevalence)
- Limited URI analysis (1.4% prevalence)

**2024 gaps:**
- No URI domain validation
- No form field analysis
- No temporal validation
- No annotation chain analysis

### Phase 2.1: High-Confidence Rules (2 days)

**New YARA rules for 2024 patterns:**

1. **Phishing URI Detection**
   ```yara
   rule pdf_phishing_uri_suspicious {
       meta:
           description = "PDF with suspicious URI patterns (2024 threat)"
           severity = "high"
           confidence = "probable"
           attack_vector = "phishing"

       strings:
           // Suspicious TLDs
           $uri_tld1 = /\/URI\s*\(http[s]?:\/\/[^\)]+\.tk[\)\/]/ nocase
           $uri_tld2 = /\/URI\s*\(http[s]?:\/\/[^\)]+\.ml[\)\/]/ nocase
           $uri_tld3 = /\/URI\s*\(http[s]?:\/\/[^\)]+\.ga[\)\/]/ nocase

           // IP-based URIs (no domain)
           $uri_ip = /\/URI\s*\(http[s]?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase

           // Obfuscated URIs (hex/unicode encoding)
           $uri_obfuscated = /\/URI\s*\([^\)]*\\[0-9]{3}/ nocase

       condition:
           any of ($uri_*)
   }

   rule pdf_credential_harvesting_form {
       meta:
           description = "PDF form with credential fields (2024 threat)"
           severity = "high"
           confidence = "probable"
           attack_vector = "credential_theft"

       strings:
           $acroform = /\/AcroForm/ nocase
           $field1 = /\/T\s*\((password|passwd|pwd|ssn|social)/i nocase
           $field2 = /\/T\s*\((username|user|login|email)/i nocase
           $submit = /\/SubmitForm/ nocase
           $uri_external = /\/URI\s*\(http/ nocase

       condition:
           $acroform and
           ($field1 or $field2) and
           ($submit or $uri_external)
   }
   ```

2. **Evasion Detection**
   ```yara
   rule pdf_benign_mimicry_suspicious {
       meta:
           description = "Malware mimicking benign patterns (2024 evasion)"
           severity = "medium"
           confidence = "heuristic"
           evasion_technique = "legitimacy_mimicry"

       strings:
           // Incremental updates (benign indicator)
           $xref_multiple = /xref/ nocase

           // URIs (2024 malicious pattern)
           $uri = /\/URI\s*\(http/ nocase

           // AcroForm (interactive)
           $acroform = /\/AcroForm/ nocase

           // Embedded files (payloads)
           $embedded = /\/EmbeddedFile/ nocase

           // NO signature (benign would have)
           $signature = /\/ByteRange/ nocase

       condition:
           (#xref_multiple > 3) and  // Multiple updates
           (#uri > 5) and             // Many URIs
           $acroform and              // Interactive form
           not $signature             // No signature (suspicious for this profile)
   }
   ```

3. **Still-Effective 2022 Rules**
   ```yara
   rule pdf_js_risky_api_calls {
       meta:
           description = "JavaScript with risky API calls (still relevant)"
           severity = "high"
           confidence = "probable"
           effectiveness_2022 = "12.1%"
           effectiveness_2024 = "4.3%"  // Reduced but still strong signal

       strings:
           $js = /\/JavaScript/ nocase
           $api1 = "app.launchURL"
           $api2 = "exportDataObject"
           $api3 = "importDataObject"
           $api4 = "submitForm"

       condition:
           $js and any of ($api*)
   }
   ```

**Deliverables:**
- [ ] 15-20 new YARA rules targeting 2024 patterns
- [ ] Update severity/confidence for existing rules
- [ ] Rule test suite with 2024 corpus validation

### Phase 2.2: Heuristic Updates (2 days)

**Code-based detection logic:**

1. **URI Analysis Heuristic**
   ```rust
   // crates/sis-pdf/src/analysis/uri_heuristics.rs

   pub fn analyze_uris(findings: &[Finding]) -> Vec<Finding> {
       let uris = extract_uris(findings);
       let mut new_findings = Vec::new();

       // Multiple URIs without signature
       if uris.len() > 10 && !has_signature(findings) {
           new_findings.push(Finding {
               kind: "uri_phishing_suspected",
               severity: Severity::High,
               confidence: Confidence::Probable,
               description: format!("{} URIs without digital signature", uris.len()),
               // ...
           });
       }

       // Check domain reputation (if available)
       for uri in uris {
           if is_suspicious_domain(&uri.domain) {
               new_findings.push(Finding {
                   kind: "uri_suspicious_domain",
                   severity: Severity::High,
                   // ...
               });
           }
       }

       new_findings
   }
   ```

2. **Form Field Analysis**
   ```rust
   // crates/sis-pdf/src/analysis/form_heuristics.rs

   pub fn analyze_forms(findings: &[Finding]) -> Vec<Finding> {
       if !has_acroform(findings) {
           return vec![];
       }

       let fields = extract_form_fields(findings);
       let mut new_findings = Vec::new();

       // Credential fields
       let credential_keywords = ["password", "passwd", "ssn", "social", "credit"];
       let has_credentials = fields.iter().any(|f| {
           credential_keywords.iter().any(|kw| f.name.to_lowercase().contains(kw))
       });

       if has_credentials && has_submit_action(findings) {
           new_findings.push(Finding {
               kind: "form_credential_harvesting",
               severity: Severity::High,
               // ...
           });
       }

       new_findings
   }
   ```

3. **Temporal Validation**
   ```rust
   // crates/sis-pdf/src/analysis/temporal_heuristics.rs

   pub fn analyze_temporal_anomalies(pdf: &PDF) -> Vec<Finding> {
       let updates = extract_incremental_updates(pdf);

       if updates.len() > 5 {
           // Check timestamps if available
           if let Some(timestamps) = extract_timestamps(updates) {
               let time_diffs: Vec<_> = timestamps.windows(2)
                   .map(|w| w[1] - w[0])
                   .collect();

               // Rapid updates (< 1 second between edits)
               if time_diffs.iter().any(|&d| d < 1.0) {
                   return vec![Finding {
                       kind: "incremental_update_suspicious_timing",
                       severity: Severity::Medium,
                       description: "Rapid incremental updates suggest automated generation",
                       // ...
                   }];
               }
           }
       }

       vec![]
   }
   ```

**Deliverables:**
- [ ] URI analysis heuristics implementation
- [ ] Form field analysis heuristics
- [ ] Temporal validation logic
- [ ] Unit tests with 2024 corpus samples

### Phase 2.3: Rule Validation (1 day)

**Testing against corpus:**

```bash
# Validate new rules against 2024 corpus
./scripts/validate_detection_rules.sh \
  /home/michiel/src/pdf-corpus/2024/malicious/VirusShare_PDF \
  rules/2024_updates/

# Expected results:
# - URI phishing rule: 47.8% detection rate
# - Credential harvesting: 15-20% detection rate
# - Benign mimicry: 25-30% detection rate
# - False positive rate (on benign): < 5%
```

**Deliverables:**
- [ ] Rule validation report
- [ ] Detection rate comparison (2022 vs 2024 rules)
- [ ] False positive analysis

---

## Track 3: Threat Intelligence Reporting

### Objective

Generate actionable threat intelligence from corpus analysis for security teams.

### Phase 3.1: Temporal Trend Report (2 days)

**Audience**: Security analysts, threat researchers, SOC teams

**Content outline:**

```markdown
# PDF Malware Evolution: 2022-2024 Threat Landscape

## Executive Summary
[Critical findings, attack vector shifts, recommendations]

## Key Statistics
- Corpus size comparison
- Detection rate changes
- Attack vector prevalence shifts

## Attack Vector Analysis
### JavaScript Exploitation (Declining)
- Prevalence: 81.7% → 22.8%
- Likely reasons: Better sandboxing, signature-based detection
- Remaining threats: 4.3% still use risky API calls

### Social Engineering (Rising)
- URI-based attacks: 1.4% → 47.8% (35.3x increase)
- Form-based credential harvesting: 18.8% → 29.5%
- Phishing infrastructure: External domains, suspicious TLDs

### Evasion Techniques
- Mimicking legitimate documents (incremental updates, proper structure)
- Reduced structural anomalies (missing EOF: 58.6% → 3.4%)
- Polymorphic obfuscation: 16.1% → 2.0% (less obvious)

## IOC Patterns

### High-Confidence Indicators (2024)
1. Multiple URIs (>10) without digital signature
2. AcroForm with credential fields + submit action
3. Annotation action chains + embedded files
4. Incremental updates + object shadowing (>50 instances)

### Medium-Confidence Indicators
1. URIs with suspicious TLDs (.tk, .ml, .ga)
2. Optional content groups (layers) + URI
3. Stream length mismatches + URIs

## Recommendations
[As outlined in corpus analysis reports]
```

**Deliverables:**
- [ ] Threat intelligence report (PDF + markdown)
- [ ] Executive summary (2 pages)
- [ ] Technical deep-dive (15-20 pages)

### Phase 3.2: IOC Feed Generation (2 days)

**Generate machine-readable IOC feeds:**

1. **STIX 2.1 Format**
   ```json
   {
     "type": "bundle",
     "id": "bundle--pdf-malware-2024",
     "objects": [
       {
         "type": "indicator",
         "pattern": "[file:mime_type = 'application/pdf' AND file:hashes.MD5 = '<hash>']",
         "valid_from": "2024-01-01T00:00:00Z",
         "labels": ["malicious-activity", "phishing"],
         "description": "PDF with URI-based phishing (2024 VirusShare)"
       },
       // ... 287K indicators
     ]
   }
   ```

2. **MISP Format**
   ```json
   {
     "Event": {
       "info": "PDF Malware Campaign 2024",
       "threat_level_id": "2",
       "analysis": "2",
       "Attribute": [
         {
           "type": "md5",
           "category": "Payload delivery",
           "value": "<hash>",
           "comment": "Malicious PDF - URI phishing"
         }
       ]
     }
   }
   ```

3. **Hash Lists**
   ```
   # MD5 hashes of 2024 malicious corpus
   # Generated from VirusShare file names

   62c8268ea4c34a47748c9df8a52124b2  # VirusShare_<hash>
   ...
   (287,777 hashes)
   ```

4. **URI/Domain Extraction**
   ```python
   # scripts/extract_iocs.py
   # Extract all URIs from malicious PDFs

   {
     "domains": [
       "malicious-domain1.tk",
       "phishing-site.ml",
       // ... unique domains
     ],
     "ips": [
       "192.0.2.1",
       // ... IP-based URIs
     ],
     "patterns": [
       "http://*/login.php",  # Common credential harvesting endpoint
       // ...
     ]
   }
   ```

**Deliverables:**
- [ ] STIX 2.1 bundle (287K indicators)
- [ ] MISP event export
- [ ] Hash lists (MD5, SHA256)
- [ ] URI/domain IOC list
- [ ] Integration guide for SIEM/TIP platforms

### Phase 3.3: Detection Signatures (1 day)

**Generate signatures for security tools:**

1. **Snort/Suricata Rules**
   ```
   # Detect PDF download with phishing characteristics
   alert http any any -> any any (
       msg:"Possible malicious PDF download (2024 pattern)";
       flow:established,to_client;
       file_data;
       content:"%PDF";
       content:"/URI";
       content:"/AcroForm";
       pcre:"/(password|login|credential)/i";
       classtype:trojan-activity;
       sid:5000001;
       rev:1;
   )
   ```

2. **Sigma Rules (SIEM)**
   ```yaml
   title: PDF Malware Download (2024 Pattern)
   id: pdf-malware-2024-001
   status: experimental
   description: Detects download of PDF with 2024 malware characteristics
   logsource:
     category: proxy
   detection:
     selection:
       c-uri|contains: '.pdf'
       cs-mime-type: 'application/pdf'
       sc-bytes: '>10000'  # Non-trivial size
     condition: selection
   falsepositives:
     - Legitimate PDF downloads
   level: medium
   ```

3. **ClamAV Signatures**
   ```
   # PDF.Phishing.2024.Generic
   # Targets URI-heavy PDFs without signatures

   pdf_phishing_2024:0:*:62c8268ea4c34a47748c9df8a52124b2
   pdf_phishing_2024:1:*:<hash2>
   # ... (hash-based for high-confidence samples)
   ```

**Deliverables:**
- [ ] Snort/Suricata rule set
- [ ] Sigma SIEM rules
- [ ] ClamAV signature database update
- [ ] Documentation for signature deployment

### Phase 3.4: Playbook Updates (2 days)

**Update incident response playbooks:**

```markdown
# Incident Response Playbook: PDF Malware (2024 Update)

## Triage (Updated)

### Quick Indicators (2024 Focus)
1. ✅ Check for digital signature (absence = suspicious)
2. ✅ Count URIs (>10 without signature = high risk)
3. ✅ Check for AcroForm with credential fields
4. ⚠️ JavaScript presence (still relevant but less common: 22.8%)
5. ✅ Incremental updates + object shadowing (evasion tactic)

### Legacy Indicators (Declining Effectiveness)
- ⚠️ Missing EOF marker (3.4% in 2024, down from 58.6%)
- ⚠️ Open actions (11.8% in 2024, down from 71.6%)
- ⚠️ Polymorphic JS (2.0% in 2024, down from 16.1%)

## Investigation Steps

### Phase 1: Automated Analysis
1. Run SIS PDF scan with deep mode
   ```bash
   sis scan suspicious.pdf --deep --jsonl-findings > findings.jsonl
   sis classify suspicious.pdf > classification.txt
   ```

2. Check classification score
   - Score > 0.8: High confidence malicious → Quarantine
   - Score 0.5-0.8: Medium → Manual analysis
   - Score < 0.5: Likely benign → Monitor

3. Extract IOCs
   ```bash
   # Extract URIs
   jq -r 'select(.finding.kind=="uri_present") | .finding.evidence[] | .note' findings.jsonl

   # Extract form submit destinations
   jq -r 'select(.finding.kind=="acroform_present")' findings.jsonl
   ```

### Phase 2: Manual Analysis (If score 0.5-0.8)
1. **URI Analysis**
   - Check domain age (whois, VirusTotal)
   - Verify TLD reputation
   - Compare displayed text vs actual URL
   - Check for typosquatting

2. **Form Analysis**
   - Identify field types
   - Check submit action destination
   - Validate if credential fields present

3. **Temporal Analysis**
   - Check creation/modification timestamps
   - Validate incremental update timeline
   - Look for rapid edits (< 1 second)

4. **JavaScript Analysis** (if present)
   - Review sandbox execution log
   - Check for network intent
   - Validate API calls (app.launchURL, etc.)

### Phase 3: Containment
[Existing procedures - quarantine, network blocking, etc.]

## Updated Detection Logic

### 2024 Detection Flow
```
1. Digital signature present?
   YES → Likely benign (proceed with caution)
   NO  → Continue analysis

2. URI count > 10?
   YES → High risk (phishing suspected)
   NO  → Continue

3. AcroForm with credential fields?
   YES → High risk (harvesting suspected)
   NO  → Continue

4. JavaScript with risky API calls?
   YES → High risk (exploitation suspected)
   NO  → Continue

5. Incremental updates + object shadowing > 50?
   YES → Medium risk (evasion suspected)
   NO  → Low risk
```
```

**Deliverables:**
- [ ] Updated incident response playbook
- [ ] Triage decision tree (2024 focus)
- [ ] Analyst training materials
- [ ] Quick reference card (one-page)

---

## Implementation Timeline

### Week 1: Data Preparation & Feature Engineering
- Days 1-2: Extract ML features, create splits
- Days 3-5: Engineer new features (URI, form, temporal)

### Week 2: Model Training & Evaluation
- Days 1-3: Train models (XGBoost, RF, ensemble)
- Days 4-5: Evaluate, error analysis, threshold tuning

### Week 3: Detection Rules & Deployment Prep
- Days 1-2: Write YARA rules, heuristics
- Days 3-4: Model export, Rust integration
- Day 5: Validation and testing

### Week 4: Threat Intelligence & Documentation
- Days 1-2: Generate threat reports, IOC feeds
- Days 3-4: Create signatures, update playbooks
- Day 5: Final review and release

### Total Duration: 4 weeks (20 working days)

---

## Success Criteria

### Model Performance
- [x] AUC > 0.90 on 2024 test set
- [x] Precision > 90%, Recall > 85% on 2024 malicious
- [x] False positive rate < 10% on 2022 benign
- [x] Temporal robustness (2022 → 2024 performance maintained)

### Detection Coverage
- [x] URI-based attacks: >90% detection rate
- [x] Credential harvesting forms: >80% detection rate
- [x] JavaScript exploits: >95% detection rate (still effective)
- [x] Evasion techniques: >70% detection rate

### Operational Impact
- [x] Model inference < 15ms per file
- [x] No regression in throughput (2,688+ files/s)
- [x] Explainable predictions (SHAP values)
- [x] Easy integration (ONNX, CLI, API)

### Threat Intelligence
- [x] Comprehensive report (15-20 pages)
- [x] Machine-readable IOC feeds (STIX, MISP)
- [x] Updated incident response procedures
- [x] Analyst training materials

---

## Risks & Mitigations

### Risk 1: Insufficient 2024 Benign Data
**Impact**: High false positive rate on modern legitimate PDFs
**Mitigation**:
- Collect 2024 benign corpus (5-10K samples)
- Use 2022 benign as baseline + signature checking
- Conservative threshold setting (favor recall over precision initially)
- Analyst feedback loop for FP correction

### Risk 2: Feature Engineering Complexity
**Impact**: Delays in implementation, bugs in extraction
**Mitigation**:
- Reuse existing finding extraction (URI, form data already collected)
- Comprehensive unit tests with known samples
- Gradual rollout (start with simple features, add complex ones incrementally)

### Risk 3: Model Drift Over Time
**Impact**: Performance degradation as threat landscape evolves
**Mitigation**:
- Quarterly model retraining (track new samples)
- Performance monitoring in production
- A/B testing before full deployment
- Versioned models with rollback capability

### Risk 4: Integration Challenges
**Impact**: Deployment delays, performance regressions
**Mitigation**:
- Use ONNX for cross-platform compatibility
- Benchmark inference performance early
- Fallback to rule-based detection if ML unavailable
- Gradual rollout with feature flags

---

## Resource Requirements

### Personnel
- ML Engineer: 3-4 weeks (model training, evaluation)
- Backend Developer: 2 weeks (Rust integration, CLI)
- Security Analyst: 1 week (rule writing, validation)
- Technical Writer: 3 days (documentation, reports)

### Compute Resources
- Model training: 1x GPU (V100/A100) or 16-32 CPU cores
- Training duration: 8-12 hours (with hyperparameter tuning)
- Inference: CPU-only (5ms per prediction)

### Storage
- Training data: ~15 GB (JSONL features)
- Models: ~100 MB (XGBoost + ensemble)
- IOC feeds: ~50 MB (STIX, MISP, hashes)

---

## Deliverables Checklist

### Track 1: ML Models
- [ ] Feature extraction scripts
- [ ] Training/validation datasets
- [ ] Trained models (XGBoost, RF, ensemble)
- [ ] Evaluation reports (metrics, error analysis)
- [ ] ONNX model exports
- [ ] Rust classifier integration
- [ ] CLI `classify` command
- [ ] Model deployment documentation

### Track 2: Detection Rules
- [ ] 15-20 new YARA rules (2024 patterns)
- [ ] URI analysis heuristics (Rust)
- [ ] Form field analysis heuristics (Rust)
- [ ] Temporal validation logic (Rust)
- [ ] Rule validation report
- [ ] Unit tests for new detections

### Track 3: Threat Intelligence
- [ ] Temporal trend report (PDF + markdown)
- [ ] Executive summary (2 pages)
- [ ] IOC feeds (STIX, MISP, hash lists)
- [ ] URI/domain extraction
- [ ] Snort/Suricata rules
- [ ] Sigma SIEM rules
- [ ] Updated incident response playbook
- [ ] Analyst training materials

---

## Post-Implementation

### Continuous Improvement
1. **Quarterly corpus updates**
   - Collect new malicious samples (VirusShare, MalwareBazaar)
   - Collect benign samples (corporate documents, public datasets)
   - Retrain models with updated data

2. **Performance monitoring**
   - Track false positive/negative rates in production
   - Collect analyst feedback on misclassifications
   - A/B test model updates before deployment

3. **Threat landscape tracking**
   - Monitor for new attack vectors
   - Update detection rules as needed
   - Publish quarterly threat reports

### Future Enhancements
1. **Content analysis** (Phase 2)
   - NLP for phishing text detection
   - OCR for image-based content
   - Similarity clustering for campaign tracking

2. **Network analysis** (Phase 3)
   - Live domain reputation checks
   - Threat actor infrastructure mapping
   - Automated IOC enrichment

3. **Behavioral analysis** (Phase 4)
   - PDF reader sandbox integration
   - Runtime behavior monitoring
   - Exploit detection in real environments

---

**Plan Status**: Ready for implementation
**Next Step**: Kick off Track 1 Phase 1.1 (dataset preparation)
**Owner**: TBD
**Review Date**: Weekly progress reviews during 4-week implementation
