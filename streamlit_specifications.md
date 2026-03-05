

# Streamlit App Specification: Adversarial & Security Test Bank Builder

## 0. One-paragraph summary
This application is a threat-driven security testing workbench designed for Security Engineers to evaluate AI systems (LLMs and ML APIs) against adversarial risks. The tool allows users to define a system under test, author or load a structured security test bank, execute deterministic evaluations using heuristic and perturbation-based logic, and generate audit-ready, cryptographically hashed evidence. By moving from manual ad-hoc testing to a systematic, schema-validated workflow, organizations can provide forensic evidence of security resilience before model deployment.

## 1. Functional Equivalence Contract

### 1.1 What must stay identical to the notebook
- **Mock Logic:** The heuristic detection in `mock_llm_chatbot` (instruction overrides, sensitive data access, code execution) and the perturbation logic in `mock_ml_scoring_api` (range checks for age/income/credit) are the core "evaluators" and must be used exactly as implemented.
- **Test Bank Schema:** The fields `test_id`, `threat_category`, `test_input`, `expected_safe_behavior`, and `severity_level` are non-negotiable.
- **Result Logic:** The logic in `execute_security_tests` that determines a `PASS` or `FAIL` based on the interaction between mock outputs and expected behaviors.
- **Risk Taxonomy:** The lists `THREAT_CATEGORIES` and `SEVERITY_LEVELS` must remain strictly as defined in `source.py`.

### 1.2 Forbidden changes
- **No External Models:** Do not replace the mocked functions with live LLM API calls (unless specifically extended).
- **No Metric Changes:** Do not add standard ML metrics (Accuracy/F1) as this is a security testing lab, not a performance lab.
- **No Data Units:** Do not change "income" to "income_k" or alter the established credit score range [300, 850].

## 2. Data Contract & Validation

### 2.1 Canonical schema
This schema applies to the test bank (JSON/List of Dicts).

| Column Name | Role | dtype | unit | allowed range | required (Y/N) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `test_id` | ID | string | - | unique identifier | Y |
| `threat_category` | Feature | string | - | See `THREAT_CATEGORIES` | Y |
| `test_input` | Feature | str/dict | - | Text (LLM) or JSON (ML) | Y |
| `expected_safe_behavior`| Target/Label | str/dict | - | Expected block/error | Y |
| `severity_level` | Feature | string | - | See `SEVERITY_LEVELS` | Y |

### 2.2 Validation behavior
- **Missing Required Keys:** Hard fail with `st.error` if any of the columns above are missing in an uploaded JSON.
- **Invalid Categories:** Hard fail if `threat_category` is not in the predefined list.
- **Type Mismatch:** For ML API inputs, `age` must be numeric (0-120), `income` non-negative, and `credit_score` (300-850).
- **Empty Tests:** The system must reject a test bank with zero entries.

### 2.3 Upload handling
- **Formats:** JSON only.
- **Size Limit:** 5MB.
- **UI:** A "Data Inspector" component after upload that calls `validate_test_bank` and displays a preview of the first 5 test cases.

## 3. UX / IA: Pages, Layout, and State Machine

### 3.1 Information architecture
- **Sidebar:** Navigation selectbox, System Type toggle (LLM vs ML_API), System Name text input.
- **Page 1: System Configuration:** Overview of the persona and selection of the AI system type.
- **Page 2: Test Bank Editor:** Interface to view, add, or upload test cases.
- **Page 3: Execution Engine:** Triggering the deterministic runs against the mocks.
- **Page 4: Findings Dashboard:** Visualizing pass/fail rates and severity distribution.
- **Page 5: Export & Audit:** Generating the report, manifest, and SHA-256 hashes.

### 3.2 Workflow gates & resets
- **Gate 1:** System Type and System Name must be set to access the Editor.
- **Gate 2:** `test_bank` must contain at least 1 validated entry to access Execution.
- **Gate 3:** `test_execution_results` must be generated to access the Dashboard or Export.
- **Reset Policy:** Changing the "System Type" in the sidebar clears the `test_bank`, `execution_results`, and `findings` to ensure cross-contamination does not occur.

### 3.3 Loading states
- **Execution:** `with st.spinner("Running deterministic security probes...")`
- **Hashing:** `with st.spinner("Calculating SHA-256 integrity hashes...")`

## 4. Application Overview
The app guides a **Security Engineer** through the process of "Adversarial Stress Testing." 
1. **Model Surface Identification:** Defining if the target is a prompt-based chatbot or a structured API.
2. **Authoring Probes:** Creating specific inputs designed to trigger failures (e.g., prompt injections).
3. **Automated Evaluation:** Using rule-based mocks to determine if the system's defenses (heuristics/perturbations) hold.
4. **Audit Reporting:** Producing a hashed manifest that proves when and how the system was tested, satisfying regulatory and risk governance requirements.

## 5. App Architecture

### 5.1 Separation of concerns
- `app.py`: Manages the Streamlit session state, navigation, and rendering logic.
- `source.py`: Pure functions for hashing, mocking, testing, and report generation.

### 5.2 Public functions imported from `source.py`
```python
from source import (
    get_mocked_ai_system,
    create_test_case,
    generate_synthetic_test_banks,
    validate_test_bank,
    execute_security_tests,
    classify_and_summarize_findings,
    generate_executive_summary_report,
    export_artifacts,
    generate_sha256_hash,
    THREAT_CATEGORIES,
    SEVERITY_LEVELS
)
```

### 5.3 Determinism & caching
- **Deterministic Mocks:** Since the logic is heuristic/regex-based, no random seed is strictly required for the simulation, but `random.seed(42)` is set in `source.py` for future-proofing.
- **Caching:** 
    - Use `@st.cache_data` for `generate_synthetic_test_banks`.
    - Use `@st.cache_data` for `execute_security_tests` keyed by the hash of the test bank and system type.

## 6. Robustness, Fallbacks, and Auditability

### 6.1 Failure modes checklist
- **Malformed ML Input:** If a user authors an ML test case with a string for `age`, the app must catch the `TypeError` during validation, not during execution.
- **Invalid JSON Upload:** Use `try-except json.JSONDecodeError` and display a clear error banner.
- **Directory Permissions:** Ensure the `reports/` directory is writable or use temporary directories for Streamlit Cloud compatibility.

### 6.2 Fallback policy
- If the `mock_llm_chatbot` fails to detect a known pattern, it returns a "Standard response," and the `execute_security_tests` logic will mark it as `FAIL` if the `expected_safe_behavior` was a block.

### 6.3 Export manifest
The manifest (generated by `export_artifacts`) must include:
- `run_id`
- Timestamp
- SHA-256 hashes for: `security_test_bank.json`, `test_execution_results.json`, `findings_summary.json`, and `session07_executive_summary.md`.

## 7. Code Requirements

### Page 1: System Selection
- **Content:** Display `MARKDOWN["intro"]` and `MARKDOWN["defining_system"]`.
- **Widgets:** 
    - `st.sidebar.selectbox` for System Type.
    - `st.sidebar.text_input` for System Name (Default: "Enterprise Chatbot").
- **Action:** Store selection in `st.session_state.system_type`.

### Page 2: Test Bank Editor
- **Content:** Display `MARKDOWN["crafting_test_bank"]`.
- **Functionality:** 
    - Button: "Load Standard Test Bank" (Calls `generate_synthetic_test_banks`).
    - File Uploader: "Upload Custom Test Bank (.json)".
    - Data Editor: `st.data_editor` to allow the user to modify or add new test cases to `st.session_state.test_bank`.
- **Validation:** Call `validate_test_bank(st.session_state.test_bank)` before proceeding.

### Page 3: Execute Tests
- **Content:** Display `MARKDOWN["executing_tests"]`.
- **Formula:**
  st.markdown(r"""$$
  \text{output} \supseteq \text{expected\_safe\_behavior} \quad \text{or} \quad \text{output} \not\ni \text{sensitive\_keyword}
  $$""")
  st.markdown(r"where $\supseteq$ represents substring matching or heuristic pattern containment.")
- **Action:** 
    - `st.button("Run Security Evaluation")`
    - Logic: 
        1. Get mock function via `get_mocked_ai_system(system_type)`.
        2. Call `execute_security_tests(...)`.
        3. Save to `st.session_state.execution_results`.

### Page 4: Findings Dashboard
- **Content:** Display `MARKDOWN["classifying_findings"]`.
- **Visuals:** 
    - `st.dataframe` showing the full result table.
    - `st.metric` cards for "Total Fails" and "Critical Vulnerabilities".
    - `st.bar_chart` of failures by `threat_category` and `severity_level`.
    - `st.warning` or `st.error` list for any "Critical" severity failures detected.

### Page 5: Export & Audit
- **Content:** Display `MARKDOWN["audit_artifacts"]`.
- **Formula:**
  st.markdown(r"""$$
  H = \text{SHA256}(\text{File Content})
  $$""")
  st.markdown(r"where $H$ is the 256-bit cryptographic fingerprint ensuring forensic integrity.")
- **Action:** 
    - `st.button("Generate Audit Bundle")`
    - Logic:
        1. Call `classify_and_summarize_findings`.
        2. Call `generate_executive_summary_report`.
        3. Use `save_json_artifact` and `save_markdown_artifact`.
        4. Call `export_artifacts`.
    - UI: Display the `evidence_manifest.json` in an `st.expander`.
    - Provide `st.download_button` for the MD report and a JSON bundle.

```python
# State Initialization Template
if "test_bank" not in st.session_state:
    st.session_state.test_bank = []
if "execution_results" not in st.session_state:
    st.session_state.execution_results = None
if "run_id" not in st.session_state:
    st.session_state.run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
```

