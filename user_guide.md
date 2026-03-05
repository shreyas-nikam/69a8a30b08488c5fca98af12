id: 69a8a30b08488c5fca98af12_user_guide
summary: Lab 7: Adversarial & Security Test Bank Builder - Clone User Guide
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# QuLab: Adversarial & Security Test Bank Builder

## Introduction and Context
Duration: 0:05:00

In the rapidly evolving landscape of Artificial Intelligence, ensuring the security and robustness of AI systems is paramount. The **QuLab: Adversarial & Security Test Bank Builder** is a comprehensive tool designed for Security Engineers to evaluate AI systems—specifically Large Language Models (LLMs) and Machine Learning (ML) APIs—against potential vulnerabilities.

The core concept of this application is **Adversarial Testing**. This involves intentionally providing malicious or unexpected inputs to a system to see if it behaves in an unsafe manner. By building a structured "Test Bank," organizations can systematically probe their AI models for weaknesses like prompt injections, data leakage, or biased outputs within a "Safe Harbor" environment that doesn't risk production data.

Through this codelab, you will learn how to:
1.  Define the attack surface of an AI system.
2.  Author and manage structured security test cases.
3.  Execute a deterministic evaluation engine to identify vulnerabilities.
4.  Analyze security metrics and export forensic-ready audit logs.

<aside class="positive">
<b>Key Concept:</b> A "Safe Harbor" environment allows security professionals to simulate attacks without affecting the actual user-facing application or its data integrity.
</aside>

## System Configuration
Duration: 0:02:00

The first step in any security assessment is defining the target. In this application, you begin by selecting the **AI System Type** you wish to test. This selection defines the "Attack Surface"—the different points where an attacker could potentially interact with the system.

Currently, the application supports two primary types of systems:
1.  **LLM (Large Language Model):** Focuses on prompt-based interfaces, such as chatbots or text generators. The primary risks here involve text manipulations like "Prompt Injection."
2.  **ML_API (Machine Learning API):** Focuses on structured data inputs, such as credit scoring or risk assessment APIs. The risks here often involve feature manipulation or "Adversarial Examples" in data.

Once you select the system type, the application automatically loads a relevant synthetic test bank to get you started.

## Test Bank Authoring and Editing
Duration: 0:07:00

A security test bank is a collection of structured test cases. Each case is designed to probe a specific security concern. In this step, you act as a Security Author to refine the tests.

A valid security test case consists of:
- **Test ID:** A unique identifier for the case.
- **Threat Category:** The type of attack being simulated (e.g., Prompt Injection, PII Leakage).
- **Test Input:** The actual malicious payload or data sent to the AI.
- **Expected Safe Behavior:** How the system *should* respond if it is secure.
- **Severity Level:** The risk impact if the test fails (Low, Medium, High, Critical).

The application provides two ways to manage these tests:
- **Bulk Upload:** You can upload a custom `security_test_bank.json` file. The system validates the JSON structure to ensure all required fields are present.
- **Inline Editor:** An interactive data grid allows you to modify test cases on the fly, add new rows, or delete irrelevant tests.

<aside class="negative">
<b>Warning:</b> Ensure that every <b>test_id</b> is unique. Duplicate IDs will prevent the system from accurately tracking results during the execution phase.
</aside>

## Executing Security Tests
Duration: 0:04:00

Once your test bank is finalized, it is time to trigger the **Evaluation Engine**. This engine simulates the interaction between an attacker (providing the "Test Input") and the AI system.

The engine follows a deterministic logic to determine if a system is "Vulnerable" or "Secure" based on the following formula:

$$ \text{Result} = \begin{cases} \text{PASS} & \text{if } \text{Actual Output} \approx \text{Expected Safe Behavior} \\ \text{FAIL} & \text{otherwise} \end{cases} $$

When you run the evaluation, the engine:
1.  Sends the inputs to a mocked version of the AI system.
2.  Captures the actual output.
3.  Compares the actual output against your defined "Expected Safe Behavior."
4.  Classifies the findings based on threat categories and severity.

## Analyzing Findings
Duration: 0:05:00

After execution, the **Findings Dashboard** provides a high-level view of the system's security posture. This dashboard translates raw test results into actionable risk metrics.

Key metrics displayed include:
- **Total Tests Evaluated:** The scope of the current audit.
- **System Pass Rate:** The percentage of tests where the AI behaved safely.
- **Critical Failures:** The count of high-stakes vulnerabilities that require immediate remediation.

The application also provides a detailed table of failures. Failures are color-coded based on severity:
- **Red (Critical):** Immediate attention required. These often represent direct bypasses of safety filters.
- **Orange (High):** Significant vulnerabilities that could lead to data exposure or system misuse.

Reviewing these failures allows security engineers to understand *where* the model's defenses are failing and *what* kind of inputs are causing the breakdown.

## Audit Export and Forensic Integrity
Duration: 0:03:00

The final phase of the security workflow is documentation. In a professional setting, security assessments must be reproducible and tamper-proof.

The **Audit Export** feature generates a comprehensive security export package. To ensure forensic integrity, the application uses cryptographic hashing. Each file in the export bundle is hashed to ensure that the findings cannot be altered after the audit is finalized.

The integrity is verified using the SHA256 algorithm:
$$ H = \text{SHA256}(\text{File Content}) $$

The exported **Audit Bundle (ZIP)** includes:
1.  The original **Security Test Bank** used.
2.  The raw **Execution Results**.
3.  A **Findings Summary** in JSON format.
4.  An **Executive Summary Report** in Markdown, providing a human-readable overview of the risk assessment.

<aside class="positive">
<b>Best Practice:</b> Always download and archive the Audit Bundle for compliance purposes. It serves as evidence of the security testing performed at a specific point in time.
</aside>
