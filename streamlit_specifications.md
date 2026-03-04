
# Streamlit Application Specification: Adversarial & Security Test Bank Builder

## 1. Application Overview
The **Adversarial & Security Test Bank Builder** is a specialized tool for **Security Engineers**, **ML Engineers**, and **AI Risk Leads** to operationalize security testing for AI systems. The application allows users to author a structured bank of adversarial test cases, execute them against deterministic mocks (LLM heuristics or ML perturbation logic), and generate audit-ready evidence manifests.

### High-Level Story Flow
1.  **System Configuration:** The user selects the target AI system type (LLM Chatbot or ML Scoring API).
2.  **Test Authoring:** The user reviews existing test cases in the "Test Bank" and adds new custom cases targeting specific threat categories (e.g., Prompt Injection, Data Leakage).
3.  **Deterministic Execution:** The user runs the test bank against a mocked environment that simulates either heuristic-based blocks (for LLMs) or boundary-check failures (for ML APIs).
4.  **Risk Assessment:** The user analyzes aggregated findings via a dashboard that highlights failures by severity and category.
5.  **Audit Export:** The user generates a cryptographically hashed export bundle including the test bank, raw results, a findings summary, and an executive markdown report.

---

## 2. Code Requirements

### Import Statement
```python
from source import *
```

### UI Interaction to Function Mapping
| UI Component | Action | Function Called from `source.py` |
| :--- | :--- | :--- |
| **System Type Radio** | Select "LLM" or "ML_API" | `get_mocked_ai_system(system_type)` |
| **Test Case Form** | Create new test case | `create_test_case(...)` |
| **"Run Security Assessment" Button** | Execute all tests | `execute_security_tests(...)` |
| **Dashboard Component** | Aggregate results | `classify_and_summarize_findings(...)` |
| **"Finalize Audit Report" Button** | Generate MD report | `generate_executive_summary_report(...)` |
| **Export Engine** | Generate file hashes | `generate_sha256_hash(file_path)` |
| **Export Engine** | Save JSON data | `save_json_artifact(data, filename)` |

### Session State Management
| Key | Purpose | Initialization Value |
| :--- | :--- | :--- |
| `system_type` | Tracks the active AI system under test | `"LLM"` |
| `test_bank` | List of authored test cases | `sample_llm_test_bank_data` (default) |
| `test_results` | Results from the latest execution | `[]` |
| `findings_summary` | Categorized stats of failures | `None` |
| `audit_ready` | Boolean gating the export section | `False` |
| `run_id` | Unique ID for the current session | `datetime...strftime(...)` |

---

## 3. Application Structure and Flow

### Page 1: System Configuration
*   **Persona Intro:** Use `st.info` to describe the role of the Security Engineer at SecureAI Solutions Inc.
*   **Selection Logic:** 
    *   A radio button selects between `LLM` and `ML_API`.
    *   **Logic:** Changing this selection triggers a state reset for `test_results` and `findings_summary`. It also updates `st.session_state.test_bank` to the corresponding sample data (`sample_llm_test_bank_data` or `sample_ml_api_test_bank_data`).
*   **System Description:** Use `st.markdown` to explain the heuristic logic (LLM) vs. perturbation logic (ML API) using content from the Section 2 explanation in `source.py`.

### Page 2: Security Test Bank Editor
*   **Table View:** Display `st.session_state.test_bank` as a `st.dataframe`.
*   **Authoring Form:**
    *   Input fields for `test_id`, `threat_category` (dropdown from `THREAT_CATEGORIES`), `severity_level` (dropdown from `SEVERITY_LEVELS`).
    *   Conditional `test_input`: Text area for LLM; JSON editor/Dictionary-like inputs for ML (Age, Income, Credit Score).
    *   Submit button calls `create_test_case` and appends the result to `st.session_state.test_bank`.

### Page 3: Execution Engine
*   **Execution Trigger:** A "Execute Deterministic Tests" button.
*   **Workflow:**
    1.  Calls `execute_security_tests(st.session_state.test_bank, MOCKED_AI_SYSTEM, st.session_state.system_type)`.
    2.  Displays a progress bar.
    3.  Stores the output in `st.session_state.test_results`.
*   **Result Table:** Show the results using `pd.DataFrame(st.session_state.test_results)`. Use `st.dataframe` with column configuration to color-code `test_result` (PASS = Green, FAIL = Red).

### Page 4: Findings Dashboard
*   **Logic:** Only render if `st.session_state.test_results` is not empty.
*   **Aggregation:** Call `classify_and_summarize_findings`.
*   **Metrics:** 
    *   Three `st.metric` columns: Total Tests, Total Pass, Total Fail.
    *   Status indicator: Large header showing `findings_summary['overall_status']`.
*   **Risk Breakdown:**
    *   Bar charts (or tables) showing failures by `severity_level` and `threat_category`.
*   **Critical Alerts:** If `critical_failures` exists, display them in an `st.error` block with specific details from the failure notes.

### Page 5: Audit & Export Bundle
*   **Report Generation:** 
    *   Call `generate_executive_summary_report`.
    *   Display the generated Markdown using `st.markdown`.
*   **Integrity Verification:**
    *   The app must save all artifacts using `save_json_artifact` and `save_markdown_artifact`.
    *   It then iterates through files and calls `generate_sha256_hash`.
*   **Mathematical Formula Rendering:**
    ```python
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    ```
    ```python
    st.markdown(r"where $H$ is the 256-bit cryptographic hash value used to ensure the forensic integrity of the audit evidence.")
    ```
*   **Evidence Manifest:** Render a JSON block showing the file names and their corresponding SHA-256 hashes.
*   **Final Export:** Provide a success message indicating the directory where artifacts are stored (using `CURRENT_REPORT_DIR`).

---

## 4. Typography & Accessibility
*   **Typography:** Use `st.set_page_config` to ensure a clean layout.
*   **Severity Highlighting:** 
    *   Critical: `st.error` or Red Background.
    *   High: `st.warning` or Orange Background.
    *   Medium/Low: `st.info` or Blue/Gray.
*   **JSON Display:** Use `st.json` for all raw feature vectors and API responses to ensure readability for the ML Engineer persona.

---

## 5. Input Context Implementation
*   **Grounding Logic:** The app must explicitly reference the logic for Pass/Fail as defined in the `execute_security_tests` function (e.g., checking for the `validated` flag in the response dictionary).
*   **ML API Schema:** When `system_type` is `ML_API`, the input form must strictly enforce the fields `age`, `income`, and `credit_score` to match the `mock_ml_scoring_api` expectations.
```python
# Validation Constraints for ML API Inputs
# Age: 0 < age < 120
# Income: >= 0
# Credit Score: 300 <= credit_score <= 850
```
---
