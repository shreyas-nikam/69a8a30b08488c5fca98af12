# QuLab: Adversarial & Security Test Bank Builder

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Testing-red?style=for-the-badge)

## 📋 Project Overview

The **Adversarial & Security Test Bank Builder** is a specialized security engineering tool designed to build, operationalize, and audit threat-driven test banks for AI systems. Developed as part of the QuLab series, this application allows security professionals to evaluate the robustness of Large Language Models (LLMs) and Machine Learning (ML) APIs against adversarial attacks such as prompt injection, data leakage, and model inversion.

The platform provides a structured workflow to transition from initial system configuration to full cryptographic audit logging, ensuring that AI deployments meet rigorous security standards.

---

## ✨ Key Features

### 1. System Configuration
*   **Target Selection:** Toggle between **LLM** and **ML API** architectures.
*   **State Management:** Intelligent session handling that clears downstream data when switching system types to maintain data integrity.

### 2. Test Bank Editor
*   **Industry Baselines:** Load standard adversarial test cases for rapid benchmarking.
*   **Custom Authoring:** Create specific test cases defining:
    *   Threat Category (Prompt Injection, Jailbreak, etc.)
    *   Input Payload
    *   Expected Safe Behavior
    *   Severity Level (Low to Critical)

### 3. Deterministic Execution Engine
*   **Mock Integration:** Runs tests against simulated AI environments.
*   **Heuristic Logic:** Uses keyword-block checks for LLMs and perturbation analysis (range/type checks) for ML APIs.
*   **Visual Feedback:** Real-time pass/fail indicators with detailed execution notes.

### 4. Findings & Risk Dashboard
*   **Aggregated Metrics:** View total tests, failure rates, and critical vulnerabilities.
*   **Data Visualization:** Interactive bar charts illustrating failures by severity and threat category.
*   **Critical Alerts:** High-visibility warnings for detected critical security failures.

### 5. Audit & Export (Forensic Integrity)
*   **Cryptographic Verification:** Generates SHA-256 hashes for every exported artifact to ensure forensic integrity.
*   **Compliance Bundling:** Exports Executive Summaries (Markdown), Execution Results (JSON), and Metadata into a timestamped audit package.
*   **Evidence Manifest:** Provides a verifiable list of all generated files and their corresponding hashes.

---

## 🛠️ Technology Stack

*   **Frontend/App Framework:** [Streamlit](https://streamlit.io/)
*   **Data Processing:** [Pandas](https://pandas.pydata.org/)
*   **Visualization:** [Matplotlib](https://matplotlib.org/) (Agg backend)
*   **Typography:** [Inter Font System](https://rsms.me/inter/)
*   **Security:** SHA-256 Hashing for file integrity
*   **Formatting:** LaTeX for mathematical notations

---

## 🚀 Getting Started

### Prerequisites

*   Python 3.8 or higher
*   `pip` package manager

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/qulab-security-test-builder.git
    cd qulab-security-test-builder
    ```

2.  **Install dependencies:**
    ```bash
    pip install streamlit pandas matplotlib
    ```

3.  **Ensure Project Structure:**
    The application requires a `source.py` file in the root directory containing the business logic (functions like `load_test_bank`, `execute_security_tests`, etc.).

### Running the Application

Launch the Streamlit server from your terminal:

```bash
streamlit run app.py
```

The application should now be accessible at `http://localhost:8501`.

---

## 📁 Project Structure

```text
.
├── app.py                # Main Streamlit application interface
├── source.py             # Business logic and helper functions (Required)
├── .streamlit/
│   └── config.toml       # Theme and typography configuration
├── reports/              # Generated audit bundles (auto-created)
│   └── RUN_[TIMESTAMP]/  # Specific run artifacts
└── README.md             # Project documentation
```

---

## 🔒 Security & Compliance

This tool implements a deterministic audit trail. When generating an audit bundle, the application calculates the hash $H$ for each file:

$$ H = \text{SHA256}(\text{File Content}) $$

This ensures that the security assessment evidence remains untampered with throughout the compliance review process.

---

## 🤝 Contributing

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/SecurityFeature`)
3. Commit your Changes (`git commit -m 'Add some SecurityFeature'`)
4. Push to the Branch (`git push origin feature/SecurityFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ✉️ Contact

**QuantUniversity** - [info@quantuniversity.com](mailto:info@quantuniversity.com)  
**Project Link:** [https://www.quantuniversity.com](https://www.quantuniversity.com)

---
*Disclaimer: This tool is intended for security testing and educational purposes. Always ensure you have permission before performing adversarial testing on third-party AI systems.*