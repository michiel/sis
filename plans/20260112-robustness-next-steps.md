 Looking at the comprehensive plan in plans/20260111-updates-from-scans.md and comparing it to what we've completed, here are the open items:

  Major Open Tracks

  🔴 Track 1: ML Model Training (0% Complete - Entire Track)

  Duration: 2-3 weeks | Status: Not Started

  This is the biggest gap. The plan calls for:

  1. Dataset Preparation (2 days)
    - Extract ML features from 314K+ samples
    - Create train/val/test splits
    - Balance dataset (malicious/benign)
  2. Feature Engineering (3 days)
    - URI analysis features (count, domains, TLDs, obfuscation)
    - Form analysis features (credential fields, submit actions)
    - Temporal features (rapid updates, timestamp analysis)
    - JavaScript behavioral features
    - Combination/interaction features
  3. Model Training (5 days)
    - XGBoost classifier (primary)
    - Random Forest (ensemble)
    - Optional: Neural network
    - Hyperparameter tuning
    - Target: AUC > 0.90 on 2024 data
  4. Evaluation (3 days)
    - Performance metrics (AUC, precision, recall)
    - Error analysis (FP/FN cases)
    - SHAP explainability
    - Temporal robustness validation
  5. Deployment Preparation (2 days)
    - ONNX model export
    - Rust integration (sis classify command)
    - Feature extraction pipeline
    - Inference API

  🟡 Track 2: Detection Rule Updates (30% Complete)

  Completed:
  - ✅ Some heuristic updates (tolerance logic, context-aware severity)
  - ✅ Object cycle detection
  - ✅ Metadata analysis

  Open (70%):

  1. Phase 2.1: High-Confidence YARA Rules (2 days) - NOT DONE
    - 15-20 new YARA rules for 2024 patterns:
        - Phishing URI detection (suspicious TLDs: .tk, .ml, .ga)
      - Credential harvesting forms
      - Benign mimicry detection
      - IP-based URIs
    - Update existing rule severity/confidence
  2. Phase 2.2: Advanced Heuristics (2 days) - PARTIALLY DONE
    - ✅ Already have: Tolerance logic, context-aware severity
    - ❌ Missing:
        - URI analysis heuristics (domain extraction, reputation checking, count-based risk)
      - Form field analysis (credential field detection, submit action validation)
      - Temporal validation (rapid update detection, timestamp analysis)
  3. Phase 2.3: Rule Validation (1 day) - NOT DONE
    - Validate new rules against 2024 corpus
    - Measure detection rates
    - False positive analysis on benign corpus

  🔴 Track 3: Threat Intelligence (0% Complete - Entire Track)

  Duration: 1 week | Status: Not Started

  1. Phase 3.1: Temporal Trend Report (2 days)
    - Executive summary of 2022→2024 evolution
    - Attack vector shift analysis (JS 81.7%→22.8%, URI 1.4%→47.8%)
    - IOC patterns and recommendations
    - 15-20 page technical report
  2. Phase 3.2: IOC Feed Generation (2 days)
    - STIX 2.1 bundle (287K indicators)
    - MISP event export
    - Hash lists (MD5/SHA256 of 287K malicious files)
    - URI/domain extraction from findings
  3. Phase 3.3: Detection Signatures (1 day)
    - Snort/Suricata rules
    - Sigma SIEM rules
    - ClamAV signature updates
  4. Phase 3.4: Playbook Updates (2 days)
    - Updated incident response procedures
    - 2024-focused triage decision tree
    - Analyst training materials

  Quick Priority Assessment

  Based on the plan's Tier 1 (Critical) recommendations:

  ✅ Done

  - Test case extraction
  - Confidence level upgrades
  - False positive reduction
  - Object cycle detection
  - Metadata analysis

  ❌ High-Priority Open Items

  1. Deploy URI analysis heuristics (2 days)
    - Addresses biggest 2024 threat (47.8% prevalence)
    - Low complexity, high impact
    - Extract from existing URI findings
  2. Update YARA rules for phishing (2-3 days)
    - Credential harvesting patterns (29.5% prevalence)
    - Suspicious TLD detection
    - Form + URI combinations
  3. Generate IOC feeds (1-2 days)
    - Network-level blocking capability
    - Hashes already available (287K samples)
    - STIX/MISP format generation
  4. Train XGBoost classifier (5-7 days)
    - Highest accuracy potential
    - Foundation for ML-based detection
    - Addresses 60-70% detection gap on 2024 samples

  Estimated Remaining Work

  - Track 1 (ML): 15-20 days (can start in parallel)
  - Track 2 (Rules): 3-5 days
  - Track 3 (Intel): 5-7 days

  Total: ~3-4 weeks of focused work to complete the full plan.

  Recommendation

  The most impactful next steps in priority order:

  1. URI analysis heuristics (2 days) - Biggest threat coverage gain
  2. YARA rule updates (2 days) - Quick deployment wins
  3. ML model training (2 weeks) - Highest long-term accuracy
  4. IOC feed generation (2 days) - Enables network defense
  5. Threat intelligence report (3 days) - Communicates findings
