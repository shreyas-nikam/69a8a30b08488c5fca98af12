
# Streamlit App Specification: Adversarial & Security Test Bank Builder

## 0. One-paragraph summary
The Adversarial & Security Test Bank Builder is an enterprise-grade tool designed for Security Engineers and AI Risk Leads to operationalize threat-driven testing for AI systems. The application allows users to toggle between testing an LLM Prompt Interface or an ML Scoring API. Users can author, edit, and manage a structured test bank containing adversarial scenarios (e.g., Prompt Injection, Data Leakage, Input Evasion). The app executes these tests against deterministic mock interfaces—using heuristic detection for LLMs and perturbation checks for ML models—aggregating results into a risk-scored findings dashboard. Finally, it generates an audit-ready export bundle, complete with a Markdown executive summary and a SHA-256 evidence manifest to ensure forensic integrity.

## 1. Functional Equivalence Contract
### 1.1 What must stay identical to the notebook
- **Mock Logic:** The `mock_llm_chatbot` (heuristic regex) and `mock_ml_scoring_api` (boundary/type checks) logic must be exactly as implemented in `source.py`.
- **Pass/Fail Logic:** The evaluation criteria in `execute_security_tests` (comparing actual output notes/status against `expected_safe_behavior`) must remain unchanged.
- **Threat Categories:** Only the specified 6 categories (Prompt Injection, Data Leakage, etc.) are supported.
- **Severity Levels:** The 4-tier system (Low, Medium, High, Critical) is non-negotiable.
- **Hashing:** The use of SHA-256 for artifact verification is mandatory.

### 1.2 Forbidden changes
- Do not add real LLM API calls; the app must use the deterministic mocks provided in `source.py`.
- Do not introduce automated attack generation (e.g., GCG or AutoDAN); testing remains focused on manually authored banks.
- Do not modify the ML feature set (`age`, `income`, `credit_score`).

## 2. Data Contract & Validation
### 2.1 Canonical schema (Test Case Bank)
| Column name | Role | dtype | unit | allowed range | required (Y/N) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `test_id` | ID | string | N/A | Unique identifier | Y |
| `threat_category` | Feature | string | N/A | See THREAT_CATEGORIES list | Y |
| `test_input` | Feature | string/dict | N/A | String (LLM) or Dict (ML) | Y |
| `expected_safe_behavior` | Target | string/dict | N/A | Expected mock response | Y |
| `severity_level` | Metadata | string | N/A | See SEVERITY_LEVELS list | Y |

### 2.2 Validation behavior
- **Test Authoring:** Any manual entry must be passed through `source.validate_test_case`. If a category or severity is invalid, the UI must display an error toast.
- **ML Input Feature Check:** For ML API systems, `test_input` must be a JSON dictionary containing `age`, `income`, and `credit_score`.
- **Duplicate IDs:** Hard fail if `test_id` is not unique within the current session bank.

### 2.3 Upload handling
- **Accepted formats:** JSON only.
- **Schema Report:** Upon upload, the app must verify the presence of all required keys and provide a "Valid Schema" green banner or a "Schema Mismatch" red banner listing missing fields.

## 3. UX / IA: Pages, Layout, and State Machine
### 3.1 Information architecture
The app uses a sidebar selectbox for navigation.
1.  **System Configuration:** Select "LLM" or "ML_API". Input the "AI System Name" (e.g., "Corporate Chatbot v1").
2.  **Test Bank Editor:** View the current bank in an `st.data_editor`. Add or delete rows. Includes a "Reset to Defaults" button using `source.get_synthetic_test_bank`.
3.  **Security Execution:** A "Run Assessment" button that triggers the batch execution logic. Displays a live progress bar.
4.  **Findings Dashboard:** Visual summary of PASS/FAIL status, failures by severity (colored bar chart), and detailed failure breakdown.
5.  **Export & Audit:** Form to trigger artifact generation. Displays the SHA-256 hashes for all generated files.

### 3.2 Workflow gates & resets
- **Gate 1:** System Type selection is required before accessing any other page. Changing the system type clears `st.session_state.test_results` and `st.session_state.findings_summary`.
- **Gate 2:** Execution requires at least 1 test case in the editor.
- **Gate 3:** Dashboard and Export are disabled until a successful execution run has completed.

### 3.3 Loading states
- `st.spinner("Executing Security Tests...")`: Used during the loop through test cases in `execute_security_tests`.
- `st.spinner("Generating Cryptographic Manifest...")`: Used during the hashing of artifacts in `export_artifacts`.

## 5. App Architecture
### 5.1 Separation of concerns
- `source.py`: Contains all detection heuristics, scoring logic, summary aggregation, and hashing.
- `app.py`: Manages the state machine, renders data tables, and handles file downloads.

### 5.2 Public functions imported from `source.py`
- `get_synthetic_test_bank(system_type: str) -> List[dict]`
- `validate_test_case(test_case: dict) -> None`
- `execute_security_tests(test_bank: List[dict], system_type: str) -> List[dict]`
- `classify_and_summarize_findings(results: List[dict]) -> dict`
- `generate_executive_summary_report(summary: dict, system_type: str, system_name: str, run_id: str) -> str`
- `export_artifacts(artifacts: dict, out_dir: str) -> dict` (Note: The manifest hash logic is inside this).

### 5.3 Determinism & caching
- `@st.cache_data` for `get_synthetic_test_bank` based on `system_type`.
- **Session State Keys:**
    - `test_bank`: The list of dicts currently being edited.
    - `test_results`: The list of dicts from the latest execution.
    - `findings_summary`: The aggregation dict.
    - `system_type`: "LLM" or "ML_API".
    - `run_id`: Created upon "Run Assessment" click.

## 6. Robustness, Fallbacks, and Auditability
### 6.1 Failure modes checklist
- **Malformed ML Input:** If a user authors a test case for ML API where `test_input` is a string instead of a dict, `source.validate_test_case` should be caught in a `try-except` block in the UI.
- **Directory Permissions:** If the app cannot write to `reports/`, display a warning to the user and offer a JSON download directly via `st.download_button` as fallback.

### 6.2 Formula Handling
The app will display the integrity verification formula in the **Export & Audit** page:
st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")

### 6.3 Export manifest
The `evidence_manifest.json` generated by `source.export_artifacts` must be displayed in a code block on the final page, showing:
- `filename`
- `sha256_hash`
- `timestamp`

### 6.4 Instructional Content (Storyline)
- **Page 1 (Configuration):** Explain that the first step in security testing is defining the "Attack Surface." LLMs are exposed via unstructured text (Prompt Interface), while ML APIs are exposed via structured feature vectors.
- **Page 2 (Editor):** Discuss the "Threat Taxonomy." Each test case is mapped to a specific risk like "Data Leakage" to ensure coverage across the OWASP Top 10 for LLMs.
- **Page 3 (Execution):** Detail the "Detection Engine." For LLMs, we use **Heuristic Detection** (Regex strings). For ML APIs, we use **Perturbation Testing** (testing how the model reacts to out-of-range values like `age: -10`).
- **Page 4 (Dashboard):** Focus on "Risk Aggregation." Not all failures are equal; a "Critical" failure in Data Leakage represents a higher business risk than a "Low" severity failure in Input Evasion.
- **Page 5 (Export):** Emphasize "Chain of Custody." In regulated AI environments, security tests must be reproducible and hashed to prove that findings haven't been tampered with post-assessment.
