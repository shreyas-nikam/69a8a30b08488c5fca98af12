id: 69a8a30b08488c5fca98af12_documentation
summary: Lab 7: Adversarial & Security Test Bank Builder - Clone Documentation
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# Adversarial & Security Test Bank Builder Codelab

## Introduction
Duration: 0:05:00

In the rapidly evolving landscape of Artificial Intelligence, ensuring the security and robustness of AI systems is paramount. Large Language Models (LLMs) and Machine Learning (ML) APIs are susceptible to various adversarial attacks, such as prompt injections and data poisoning.

This codelab introduces the **Adversarial & Security Test Bank Builder**, a Streamlit-based application designed for security engineers. This tool facilitates the creation, management, and execution of structured security test cases to probe AI systems for vulnerabilities within a "Safe Harbor" environment.

### Key Concepts Covered
- **Attack Surface Definition:** Differentiating security testing between LLM prompt interfaces and structured ML Scoring APIs.
- **Adversarial Test Banks:** Authoring structured JSON-based test cases focusing on threat categories and severity levels.
- **Deterministic Evaluation:** Executing tests where actual system outputs are compared against expected safe behaviors.
- **Forensic Integrity:** Generating audit-ready reports with cryptographic evidence (SHA256 hashing) for compliance and remediation.

<aside class="positive">
<b>Tip:</b> This application acts as a bridge between security research and practical AI deployment, allowing teams to automate the "Red Teaming" process.
</aside>

## System Configuration
Duration: 0:03:00

The first step in any security assessment is defining the **Attack Surface**. The application allows you to choose between two distinct AI system types:

1.  **LLM (Large Language Model):** Focuses on natural language prompt interfaces where vulnerabilities often include prompt injections, jailbreaks, or toxic content generation.
2.  **ML_API (Machine Learning Scoring API):** Focuses on structured data inputs (e.g., JSON) where vulnerabilities might involve input manipulation to bypass fraud detection or credit risk models.

### How it works in the code
The application manages this state using `st.session_state.system_type`. When the system type is toggled, the application reloads the appropriate synthetic test bank and clears previous results to ensure data consistency.

```python
sys_options = ["LLM", "ML_API"]
selected_sys = st.radio("Select AI System Type", sys_options, index=curr_idx)

if selected_sys != st.session_state.system_type:
    st.session_state.system_type = selected_sys
    st.session_state.test_bank = load_synthetic_banks()[selected_sys]
    st.session_state.results = None # Reset results for new context
```

## Managing the Test Bank
Duration: 0:10:00

The **Test Bank Editor** is the core component where security engineers author or modify test cases. A valid test case requires a structured schema to ensure the evaluation engine can process it accurately.

### Required Fields
Each test case must contain:
- `test_id`: A unique identifier for the test.
- `threat_category`: The type of attack (e.g., Prompt Injection, PII Leakage).
- `test_input`: The adversarial payload.
- `expected_safe_behavior`: The baseline for a passing grade (e.g., "Refuse to provide password").
- `severity_level`: Impact of a failure (Critical, High, Medium, Low).

### Inline Editing
The application utilizes `st.data_editor` to allow dynamic updates to the test cases. For ML APIs, the editor handles JSON string conversion automatically to ensure that complex objects can be edited within the table.

```python
edited_df = st.data_editor(df, use_container_width=True, num_rows="dynamic")

if st.button("Save Changes"):
    if not edited_df["test_id"].is_unique:
        st.error("Error: `test_id` values must be strictly unique.")
    else:
        # Conversion logic for ML_API inputs...
        st.session_state.test_bank = new_bank
```

<aside class="negative">
<b>Warning:</b> Ensure that `test_id` values are unique. Duplicate IDs will cause errors during the evaluation and reporting phases.
</aside>

## Executing Security Tests
Duration: 0:05:00

Once the test bank is configured, the **Evaluation Engine** simulates a red-teaming exercise. The engine probes the target system (simulated via mock functions in this lab) and compares the output to the expected safe behavior.

### Evaluation Logic
The core logic follows a deterministic pass/fail criteria:

$$ \text{Result} = \begin{cases} \text{PASS} & \text{if } \text{Actual} \approx \text{Expected Safe Behavior} \\ \text{FAIL} & \text{otherwise} \end{cases} $$

### Triggering the Engine
Clicking the "Run Evaluation Engine" button triggers the `execute_security_tests` function. This function iterates through the test bank and logs the system's responses.

```python
if st.button("Run Evaluation Engine"):
    with st.spinner("Executing Security Test Bank..."):
        sys_func = get_mocked_ai_system(st.session_state.system_type)
        results = execute_security_tests(
            st.session_state.test_bank, 
            sys_func, 
            st.session_state.system_type
        )
        st.session_state.results = results
```

## Analyzing Findings
Duration: 0:07:00

The **Findings Dashboard** provides a high-level overview of the system's security posture. It aggregates results into actionable metrics.

### Key Metrics
- **Total Tests Evaluated:** The size of the test bank.
- **System Pass Rate:** Percentage of tests that did not trigger a vulnerability.
- **Critical Failures:** A count of failed tests marked with "Critical" severity, which usually require immediate patches.

### Visualizing Failures
The dashboard highlights failures based on their severity using a custom styling function. Critical failures are highlighted in red, and High severity in orange.

```python
def highlight_severity(s):
    if s["severity_level"] == "Critical": 
        return ["background-color: #ffcccc"] * len(s)
    elif s["severity_level"] == "High": 
        return ["background-color: #ffe6cc"] * len(s)
    return [""] * len(s)

st.dataframe(fail_df.style.apply(highlight_severity, axis=1))
```

## Audit and Forensic Export
Duration: 0:05:00

The final step is the **Audit Export**. For regulatory compliance and internal security reviews, a permanent record of the test run is necessary.

### Cryptographic Integrity
To ensure that the audit logs have not been tampered with, the application calculates a SHA256 hash for the audit package.

$$ H = \text{SHA256}(\text{File Content}) $$

### The Audit Bundle
The "Finalize Security Audit" process generates a ZIP archive containing:
1.  `security_test_bank.json`: The specific cases used.
2.  `test_execution_results.json`: Raw outputs from the AI system.
3.  `findings_summary.json`: Aggregated metrics.
4.  `executive_summary.md`: A human-readable report summarizing the risk posture.

<button>
  [Download Sample Audit Format](https://www.quantuniversity.com)
</button>

## Conclusion
Duration: 0:02:00

Congratulations! You have explored the functionalities of the Adversarial & Security Test Bank Builder. 

### Summary of Workflow
1.  **Configure** the target system type (LLM or ML API).
2.  **Author** adversarial test cases in the Editor.
3.  **Execute** the evaluation engine to simulate attacks.
4.  **Analyze** vulnerabilities in the Dashboard.
5.  **Export** a cryptographically sealed audit bundle for forensic records.

By following this structured approach, developers and security researchers can build safer, more resilient AI systems.
