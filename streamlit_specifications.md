
# Streamlit Application Specification: Adversarial & Security Test Bank Builder

## 1. Application Overview
The **Adversarial & Security Test Bank Builder** is a specialized tool for Security Engineers to operationalize threat-driven testing for AI systems. The application allows users to define a "System Under Test" (either an LLM Prompt Interface or an ML Scoring API), author structured security test cases targeting specific threat categories (e.g., Prompt Injection, Data Leakage), execute those tests against deterministic mocks, and generate audit-ready evidence artifacts.

### High-Level Story Flow
1.  **System Selection:** The engineer selects the AI architecture (LLM vs. ML API) and initializes the testing session.
2.  **Test Bank Authoring:** The engineer builds a library of adversarial inputs and defines expected safe behaviors using a structured editor.
3.  **Deterministic Execution:** The tool runs the test bank against an AI interface that implements heuristic-based (LLM) or perturbation-based (ML) security checks.
4.  **Risk Assessment:** Findings are aggregated into a dashboard that highlights critical vulnerabilities and summarizes the threat posture.
5.  **Artifact Generation:** A cryptographically hashed evidence manifest and executive summary are generated for compliance and forensic audit.

---

## 2. Code Requirements

### Import Statement
```python
from source import *
```

### Session State Management
The following keys will be managed in `st.session_state`:
*   `system_type`: String ("LLM" or "ML_API"). Defaults to "LLM".
*   `test_bank`: List of dictionaries containing authored test cases.
*   `execution_results`: List of dictionaries containing PASS/FAIL data from the last run.
*   `findings_summary`: Dictionary summarizing risks.
*   `artifact_manifest`: List of file paths and hashes generated during the session.
*   `current_report_dir`: Path to the directory where artifacts are stored for the current `RUN_ID`.

### UI Interaction to Function Mapping

| UI Component | Action | Function / Logic |
| :--- | :--- | :--- |
| **System Selector** (Radio) | Selection Change | Update `st.session_state.system_type`, Clear `test_bank` and `execution_results`. |
| **Load Samples** (Button) | Click | Call `save_json_artifact` for sample data, then `load_test_bank()` and update `st.session_state.test_bank`. |
| **Add Test Case** (Form) | Submit | Call `create_test_case()` with form inputs; append to `st.session_state.test_bank`. |
| **Run Assessment** (Button) | Click | Call `get_mocked_ai_system(system_type)`, then `execute_security_tests()`. Store in `execution_results`. |
| **Summarize Findings** | Automatic/Triggered | Call `classify_and_summarize_findings()`. |
| **Export Bundle** (Button) | Click | Call `generate_executive_summary_report()`, `save_markdown_artifact()`, then iterate through files with `generate_sha256_hash()` to build manifest. |

---

## 3. Application Structure and Flow

### Page Layout
The application will use `st.tabs` to organize the workflow into five stages.

#### Tab 1: System Configuration
*   **Markdown:** Introduction to the persona (Security Engineer) and the goal of building a threat-driven test bank.
*   **Widget:** `st.radio` to select `AI_SYSTEM_TYPE` ("LLM" or "ML_API").
*   **Logic:** If the radio value changes, trigger a session state reset for downstream data to maintain consistency.

#### Tab 2: Test Bank Editor
*   **Markdown:** Explanation of the Test Case schema (ID, Category, Input, Expected Behavior, Severity).
*   **Actionable:** A "Load Industry Standard Samples" button that calls `load_test_bank` for the selected system type.
*   **Manual Entry Form:**
    *   `st.text_input` for `test_id`.
    *   `st.selectbox` for `threat_category` (using `THREAT_CATEGORIES`).
    *   `st.text_area` for `test_input` (Instructions: "Enter prompt for LLM or JSON string for ML API").
    *   `st.text_area` for `expected_safe_behavior`.
    *   `st.selectbox` for `severity_level` (using `SEVERITY_LEVELS`).
*   **Logic:** `create_test_case` is called on submission to validate fields.
*   **Display:** `st.dataframe` showing the current `st.session_state.test_bank`.

#### Tab 3: Execution Engine
*   **Requirement:** Only enabled if `len(st.session_state.test_bank) > 0`.
*   **Markdown:** Overview of deterministic execution logic. For LLMs, it uses heuristics (keyword blocks); for ML, it uses perturbation checks (range/type validation).
*   **Action:** "Execute Security Tests" button.
*   **Logic:** Calls `execute_security_tests` using `st.session_state.test_bank` and the function returned by `get_mocked_ai_system`.
*   **Display:** `st.table` or `st.dataframe` of results showing `test_id`, `test_result` (PASS/FAIL), and `notes`.
*   **Visual Cue:** Use `st.success` for PASS and `st.error` for FAIL rows.

#### Tab 4: Findings Dashboard
*   **Requirement:** Only enabled if `st.session_state.execution_results` exists.
*   **Logic:** Call `classify_and_summarize_findings`.
*   **Metrics:** `st.columns` displaying Total Tests, Total Fails, and Critical Failures.
*   **Visualizations:**
    *   `st.bar_chart` of Failures by Severity.
    *   `st.bar_chart` of Failures by Threat Category.
*   **Alert:** If `findings_summary["critical_failures"]` is not empty, display a warning using `st.warning` listing the IDs of critical failures.

#### Tab 5: Audit & Export
*   **Markdown:** Explanation of forensic integrity and hashing.
*   **Formula Rendering:**
    ```python
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    st.markdown(r"where $H$ is the 256-bit cryptographic hash used to verify that the assessment evidence has not been tampered with.")
    ```
*   **Action:** "Generate Audit Bundle" button.
*   **Logic:**
    1. Call `generate_executive_summary_report`.
    2. Save all results using `save_json_artifact` and `save_markdown_artifact`.
    3. Iterate over the `artifact_paths` to generate hashes using `generate_sha256_hash`.
    4. Save the `evidence_manifest.json`.
*   **Display:** A final table showing: Artifact Filename | Relative Path | SHA-256 Hash.
*   **Markdown:** Render the `executive_summary_content` directly in the UI for a preview.

---

## 4. Typography and Accessibility
*   **Base Font:** Sans-serif (Streamlit default).
*   **Code Blocks:** All JSON snippets and CLI commands rendered using `st.code`.
*   **Color System:**
    *   **Critical:** Red (`st.error`)
    *   **High:** Orange (`st.warning`)
    *   **Medium:** Yellow
    *   **Low/Pass:** Green (`st.success`)
*   **Input Validation:** Hard-fail logic (via `st.error` and `st.stop`) if the user attempts to add an invalid category or severity level.

---

## 5. Acceptance Criteria Verification
*   User can switch between LLM and ML API.
*   At least 1 custom test case can be added to the bank.
*   Executing tests produces a results dataframe.
*   Failures are correctly aggregated by severity.
*   The export section generates a JSON manifest containing SHA-256 strings for all files in the current `RUN_ID` directory.
