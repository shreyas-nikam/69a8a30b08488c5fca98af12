
# Specification: Lab 7 — Adversarial & Security Test Bank Builder

## 0. One-paragraph summary
The **Adversarial & Security Test Bank Builder** is an enterprise-grade utility designed for Security Engineers, ML Engineers, and AI Risk Leads to systematically evaluate AI systems against adversarial threats. The application enables users to select between LLM-based and ML API systems, author or modify a structured test bank categorized by threat vectors (e.g., Prompt Injection, Evasion), and execute these tests against deterministic mocks. The app culminates in a high-fidelity risk dashboard and an audit-ready export bundle, complete with a SHA-256 evidence manifest to ensure forensic integrity of the security assessment.

---

## 1. Functional Equivalence Contract
### 1.1 What must stay identical to the notebook
- **Logic Engines**: The heuristic-based detection in `mock_llm_chatbot` (regex for overrides, data leakage keywords) and the perturbation checks in `mock_ml_scoring_api` (boundary checks for age, income, credit) must be used exactly as defined.
- **Threat Categories**: The fixed taxonomy of 6 categories (Prompt Injection, Data Leakage, etc.) must remain unchanged.
- **Risk Metrics**: Severity-based classification and Pass/Fail logic must align with the notebook's evaluation functions.
- **Result Schema**: Every test result must include `test_id`, `threat_category`, `test_input`, `expected_safe_behavior`, `actual_output`, `test_result`, `severity_level`, and `notes`.

### 1.2 Forbidden changes
- Do not add external LLM API calls (logic must remain deterministic and mocked).
- Do not introduce new ML features beyond `age`, `income`, and `credit_score`.
- Do not modify the SHA-256 hashing requirement for evidence generation.

---

## 2. Data Contract & Validation
### 2.1 Canonical schema (Security Test Case)
| Column Name | Role | dtype | Allowed Range / Values | Required |
| :--- | :--- | :--- | :--- | :--- |
| `test_id` | ID | string | Unique alphanumeric (e.g., LLM-PI-001) | Y |
| `threat_category` | Feature | string | ["Prompt Injection", "Data Leakage", "Model Extraction", "Input Evasion", "Training Data Poisoning (Simulated)", "Unsafe Code Execution"] | Y |
| `test_input` | Feature | str/dict | String (LLM) or Dict (ML API) | Y |
| `expected_safe_behavior` | Feature | str/dict | String (LLM) or Dict (ML API) | Y |
| `severity_level` | Feature | string | ["Low", "Medium", "High", "Critical"] | Y |

### 2.2 Validation behavior
- **Schema Check**: If a JSON upload is missing any of the 5 keys above, the app must stop and display a `st.error` identifying the missing fields.
- **Dtype Coercion**: If `test_input` for an ML_API system is provided as a string instead of a dictionary, the validation layer must attempt to parse it as JSON or fail.
- **ML Boundary Rules**: 
    - `age`: $0 < age < 120$
    - `income`: $\ge 0$
    - `credit_score`: $300 \le credit\_score \le 850$
- **Severity Check**: Inputs outside the 4 specified levels must be rejected.

### 2.3 Upload handling
- **Accepted Formats**: JSON only.
- **Policy**: Users can upload a custom `security_test_bank.json`. The app validates against the `system_type` selected.

---

## 3. UX / IA: Pages, Layout, and State Machine
### 3.1 Information architecture
Navigation via Sidebar Selectbox:
1.  **System Configuration**: Choose between "LLM Prompt Interface" and "ML Scoring API".
2.  **Test Bank Editor**: View, edit, or upload test cases.
3.  **Execute Security Tests**: Run the batch processing against the mocked system.
4.  **Findings Dashboard**: Visual summary of PASS/FAIL counts and severity distribution.
5.  **Audit Export**: Generate report and evidence manifest with SHA-256 hashes.

### 3.2 Workflow gates & resets
- **Gating**: "Execute Security Tests" is disabled if the test bank is empty. "Audit Export" is disabled until a run is completed.
- **Resets**: Changing the **System Type** in Page 1 triggers a full reset of `st.session_state.test_bank` (reloading synthetic defaults) and clears all results.

### 3.3 Loading states
- `st.spinner("Executing Security Test Bank...")` during test execution.
- `st.spinner("Generating Cryptographic Evidence Manifest...")` during export.

---

## 4. App Architecture
### 4.1 Separation of concerns
- `source.py`: Contains all logic for `mock_llm_chatbot`, `mock_ml_scoring_api`, `execute_security_tests`, `classify_and_summarize_findings`, and `export_artifacts`.
- `app.py`: Handles sidebar navigation, data table rendering (`st.data_editor`), results visualization, and session state persistence.

### 4.2 Public functions imported from `source.py`
- `get_synthetic_test_banks()` -> Returns default dictionaries.
- `get_mocked_ai_system(system_type)` -> Returns the relevant mock function.
- `execute_security_tests(test_bank, mock_func, system_type)` -> Returns results list.
- `classify_and_summarize_findings(results, categories, levels)` -> Returns stats.
- `generate_executive_summary_report(summary, system_type, ...)` -> Returns Markdown string.
- `export_artifacts(artifacts, out_dir, run_id)` -> Writes files and returns manifest.

### 4.3 Determinism & caching
- `@st.cache_data` for `get_synthetic_test_banks()`.
- Seed Management: Call `set_global_seed(42)` on app initialization to ensure deterministic mock responses where applicable.

---

## 5. Page-by-Page Requirements

### Page 1: System Selection
- **Storyline**: The user takes the role of a Security Engineer defining the "Attack Surface." 
- **Interaction**: Radio buttons for "System Type".
- **Logic**: 
    - Selection sets `st.session_state.system_type`.
    - Initializes `st.session_state.test_bank` with data from `get_synthetic_test_banks()`.

### Page 2: Test Bank Editor
- **Storyline**: Define specific adversarial probes. For LLMs, this involves instruction overrides; for ML, it involves boundary-violating feature vectors.
- **UI Components**:
    - `st.data_editor` to allow inline modification of the test bank.
    - `st.file_uploader` for custom JSON banks.
- **Validation**: Ensure `test_id` remains unique.

### Page 3: Execute Security Tests
- **Storyline**: Trigger the deterministic evaluation engine. This simulates a "Safe Harbor" testing environment where the AI system is probed without risking production data.
- **Formula Presentation**:
    ```python
    st.markdown(r"$$ \text{Result} = \begin{cases} \text{PASS} & \text{if } \text{Actual} \approx \text{Expected Safe Behavior} \\ \text{FAIL} & \text{otherwise} \end{cases} $$")
    ```
- **Execution**: Button triggers `execute_security_tests`.
- **Display**: A progress bar showing progress through the test list.

### Page 4: Findings Dashboard
- **Storyline**: Aggregating the risk. A "Critical" failure in a "Prompt Injection" category represents a high-risk vulnerability.
- **Visuals**:
    - Metrics: Total Tests, Pass Rate %, Critical Failure Count.
    - Dataframe of all FAILURES specifically, highlighted by severity.
- **Logic**: Calls `classify_and_summarize_findings`.

### Page 5: Audit Export
- **Storyline**: Finalizing the assessment for the AI Risk Lead. Forensic integrity is maintained via SHA-256.
- **Formula Presentation**:
    ```python
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    ```
- **Interaction**: Button to "Finalize Audit".
- **Download**: Provides a ZIP file containing:
    1. `security_test_bank.json`
    2. `test_execution_results.json`
    3. `findings_summary.json`
    4. `executive_summary.md`
    5. `evidence_manifest.json`

---

## 6. Robustness & Fallbacks
- **Failure Mode**: User uploads a JSON with malformed dictionary keys in `test_input` for ML API.
    - **Fallback**: Display warning and skip that specific test case, recording it as an "Error" in the notes rather than a Pass or Fail.
- **Auditability**: The `evidence_manifest.json` must include the `run_id` and timestamp to ensure the exported hashes can be verified against the files in the zip.

