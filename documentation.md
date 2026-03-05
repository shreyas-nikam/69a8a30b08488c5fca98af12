id: 69a8a30b08488c5fca98af12_documentation
summary: Lab 7: Adversarial & Security Test Bank Builder - Clone Documentation
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# Adversarial & Security Test Bank Builder

## Overview
Duration: 0:05:00

In the era of Generative AI and Machine Learning, security is no longer just about network firewalls; it is about the integrity of the models themselves. This codelab introduces the **Adversarial & Security Test Bank Builder**, a specialized tool designed for Security Engineers to operationalize threat testing for AI systems.

### Importance of the Application
The application provides a structured framework to identify vulnerabilities such as:
*   **Prompt Injection:** Manipulating LLMs to ignore original instructions.
*   **Data Leakage:** Extracting sensitive training data or system information.
*   **Model Inversion:** Reconstructing training data from model outputs.
*   **Jailbreaking:** Bypassing safety guardrails.

### Concepts Covered
By following this guide, you will understand:
1.  **Threat-Driven Test Authoring:** How to define structured test cases with specific threat categories and severity levels.
2.  **Deterministic Execution:** Comparing AI outputs against expected safe behaviors.
3.  **Risk Metrics:** Visualizing failure distributions across different security domains.
4.  **Forensic Auditing:** Generating cryptographically signed evidence bundles for compliance.

<aside class="positive">
<b>Key Insight:</b> This tool utilizes a workflow-based approach to move from configuration to a full audit report, ensuring a repeatable security assessment process.
</aside>

## Application Architecture & Workflow
Duration: 0:07:00

The application is built on a modular Streamlit architecture that separates the user interface from the underlying security logic.

### Workflow Stages
The application follows a linear five-stage workflow:

1.  **System Configuration:** Defining the target architecture (LLM or ML API).
2.  **Test Bank Editor:** Creating or importing the security test cases.
3.  **Execution Engine:** Running the test suite against a mocked environment.
4.  **Findings Dashboard:** Analyzing the results and identifying critical failures.
5.  **Audit & Export:** Creating a forensic package with SHA-256 integrity hashes.

### Logical Flow Diagram
```console
[Config] -> [Author/Load Tests] -> [Mock System Execution] -> [Dashboard Analysis] -> [Audit Export]
   ^                                                                                  |
   |__________________________________________________________________________________|
```

The application uses **Streamlit Session State** to maintain data integrity as the user moves between these stages. If the system type is changed in Stage 1, the downstream data is cleared to prevent cross-contamination of test results.

## Stage 1: System Configuration
Duration: 0:03:00

The first step is to establish the context of the assessment. AI security testing differs significantly between Large Language Models (LLMs) and traditional Machine Learning APIs (ML APIs).

### Selecting the Target
In the sidebar, navigate to **1. System Configuration**.
*   **LLM:** Focuses on natural language inputs, prompt injections, and conversational safety.
*   **ML API:** Focuses on structured data, perturbation attacks, and boundary testing.

<aside class="negative">
<b>Warning:</b> Changing the AI System Type will clear your current session's test bank and execution results to ensure data consistency.
</aside>

The code handles this state change using `st.rerun()`:
```python
if new_sys_type != st.session_state.system_type:
    st.session_state.system_type = new_sys_type
    st.session_state.test_bank = []
    st.session_state.execution_results = []
    st.rerun()
```

## Stage 2: Test Bank Editor
Duration: 0:10:00

A test bank is a collection of adversarial probes. In this stage, you author the "attacks" you want to perform.

### Loading Industry Standards
Security engineers can jumpstart the process by clicking **Load Industry Standard Samples**. This calls the `load_test_bank(system_type)` function from the business logic, which pulls pre-defined baselines.

### Custom Test Case Definition
Each test case requires the following attributes:
*   **Test ID:** A unique identifier (e.g., `SEC-PROMPT-01`).
*   **Threat Category:** Categorized based on common AI risks (e.g., Denial of Service).
*   **Test Input:** The actual payload (the malicious prompt or malformed JSON).
*   **Expected Safe Behavior:** The criteria for a "PASS" (e.g., "Model should refuse to provide passwords").
*   **Severity Level:** Low, Medium, High, or Critical.

### Data Validation
The application uses a form to collect this data and validate that required fields are present before appending them to `st.session_state.test_bank`.

```python
with st.form("test_case_form"):
    # Input fields...
    if st.form_submit_button("Add Test Case"):
        new_case = create_test_case(test_id=t_id, ...)
        st.session_state.test_bank.append(new_case)
```

## Stage 3: Execution Engine
Duration: 0:08:00

The Execution Engine is where the theoretical test cases are applied to a mocked AI interface.

### Deterministic Logic
Because LLM outputs can be stochastic, the engine utilizes specific heuristics:
1.  **LLM Checks:** Heuristic keyword blocking (detecting if the model regurgitated restricted phrases).
2.  **ML API Checks:** Perturbation checks (verifying if inputs outside expected ranges are handled gracefully).

### Execution Flow
1.  Initialize the mock system via `get_mocked_ai_system()`.
2.  Pass the test bank to `execute_security_tests()`.
3.  Display visual cues: **Success/Green** for passes, **Error/Red** for failures.

<aside class="positive">
<b>Best Practice:</b> In a real-world scenario, the `mock_system` would be replaced with an actual API endpoint or model deployment.
</aside>

## Stage 4: Findings Dashboard
Duration: 0:05:00

Once execution is complete, the security engineer must synthesize the results into actionable intelligence.

### Metric Aggregation
The dashboard calculates:
*   **Total Tests Run**
*   **Total Failure Count**
*   **Critical Failure Count** (These are highlighted with a 🚨 emoji for immediate attention).

### Visualizing Risk
The application uses `st.bar_chart` to show:
*   **Failures by Severity:** Identifying if the system is failing primarily on High-risk items.
*   **Failures by Threat Category:** Identifying specific weak points (e.g., the model is safe from Prompt Injection but vulnerable to Data Leakage).

```python
summary = classify_and_summarize_findings(st.session_state.execution_results)
# Displaying metrics
col1.metric("Total Tests", summary.get("total_tests", 0))
```

## Stage 5: Audit & Export
Duration: 0:07:00

The final stage is critical for compliance and regulatory reporting. It ensures that the assessment results are tamper-proof.

### Cryptographic Forensics
The application generates a SHA-256 hash for every artifact generated (JSON results, metadata, and the markdown executive summary). 

The mathematical representation of this integrity check is:
$$ H = \text{SHA256}(\text{File Content}) $$

where $H$ is the 256-bit cryptographic hash used to verify that the assessment evidence has not been tampered with.

### Generating the Evidence Bundle
When you click **Generate Audit Bundle**, the app:
1.  Generates an Executive Summary in Markdown.
2.  Saves the raw JSON execution results.
3.  Creates an `evidence_manifest.json` containing the relative paths and the calculated SHA-256 hashes.

### Artifact Preview
The Evidence Manifest is displayed in a dataframe, allowing the user to verify the location and hash of every generated file before final export.

<aside class="positive">
<b>Summary:</b> You have successfully navigated the end-to-end process of building a security test bank, executing it, analyzing risks, and securing the findings for audit.
</aside>
