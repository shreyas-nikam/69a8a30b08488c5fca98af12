# QuLab: Adversarial & Security Test Bank Builder

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Cyber-red?style=for-the-badge)

**QuLab: Adversarial & Security Test Bank Builder** is a comprehensive security evaluation framework designed to stress-test AI systems. Whether you are deploying Large Language Models (LLMs) or traditional Machine Learning APIs, this tool allows security engineers and data scientists to build, manage, and execute adversarial test banks to identify vulnerabilities such as data leakage, input evasion, and prompt injection.

---

## 🚀 Features

- **Multi-System Support**: Tailored testing environments for **LLMs** (unstructured text) and **ML APIs** (structured feature vectors).
- **Dynamic Test Bank Editor**: Create, upload, and modify security test cases on the fly using an interactive data editor.
- **Threat Taxonomy Mapping**: Test cases are aligned with security risks like the **OWASP Top 10 for LLMs**.
- **Automated Detection Engine**: 
    - **LLMs**: Heuristic detection using regex-based string matching.
    - **ML APIs**: Perturbation testing for boundary analysis (e.g., out-of-range numerical values).
- **Risk Dashboards**: Visualize assessment results through interactive charts and severity-based failure breakdowns.
- **Audit-Ready Exports**: Generate cryptographic evidence manifests (SHA256) to ensure a "Chain of Custody" for regulatory compliance and reproducible reporting.

---

## 🛠️ Technology Stack

- **Frontend/App Framework**: [Streamlit](https://streamlit.io/)
- **Data Manipulation**: [Pandas](https://pandas.pydata.org/)
- **Visualization**: [Matplotlib](https://matplotlib.org/)
- **Security Logic**: Custom heuristic and perturbation engines
- **Audit/Hashing**: Python `uuid` and `hashlib` (standard libraries)

---

## 📋 Project Structure

```text
.
├── app.py              # Main Streamlit application file
├── source.py           # Core logic (Security execution, report generation, helpers)
├── requirements.txt    # Python dependencies
├── reports/            # Auto-generated directory for export artifacts
└── README.md           # Project documentation
```

---

## 🚦 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/qulab-adversarial-builder.git
   cd qulab-adversarial-builder
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   streamlit run app.py
   ```

---

## 📖 Usage Guide

### 1. System Configuration
Define your **Attack Surface**. Choose between `LLM` or `ML_API`. This selection determines the type of synthetic tests generated and the logic used for security detection.

### 2. Test Bank Editor
Manage your security scenarios. You can:
- Upload a custom JSON test bank.
- Edit test cases directly in the app (Input, Expected Behavior, Severity).
- Map tests to specific risk categories (e.g., Data Leakage).

### 3. Security Execution
Run the assessment engine. The app will simulate adversarial attacks against your defined system and evaluate responses based on safety heuristics or perturbation analysis.

### 4. Findings Dashboard
Review results through a high-level summary. Analyze metrics like:
- Total Pass/Fail ratio.
- Failures categorized by Severity (Critical, High, Medium, Low).
- Detailed tabular breakdown of specific test failures.

### 5. Export & Audit
Generate a compliance-ready package. The app produces:
- `executive_summary.md`: A narrative report of findings.
- `evidence_manifest.json`: A SHA256-hashed record of the run to prevent tampering.
- `test_results.json`: Raw data for further analysis.

---

## 🔒 Security & Compliance

In regulated AI environments, security tests must be reproducible. This tool implements a **Chain of Custody** feature. By generating a SHA256 hash of the content:
$$ H = \text{SHA256}(\text{File Content}) $$
Users can prove that assessment findings have not been tampered with post-execution, facilitating smoother internal and external audits.

---

## 🤝 Contributing

Contributions are welcome! If you'd like to improve the detection engines or add new visualization modules:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/NewHeuristic`).
3. Commit your changes (`git commit -m 'Add new heuristic detection'`).
4. Push to the branch (`git push origin feature/NewHeuristic`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ✉️ Contact

**QuantUniversity**  
Email: [info@quantuniversity.com](mailto:info@quantuniversity.com)  
Website: [www.quantuniversity.com](https://www.quantuniversity.com)

*Disclaimer: This tool is intended for security testing and educational purposes. Always ensure you have permission before performing adversarial testing on any production system.*

## License

## QuantUniversity License

© QuantUniversity 2025  
This notebook was created for **educational purposes only** and is **not intended for commercial use**.  

- You **may not copy, share, or redistribute** this notebook **without explicit permission** from QuantUniversity.  
- You **may not delete or modify this license cell** without authorization.  
- This notebook was generated using **QuCreate**, an AI-powered assistant.  
- Content generated by AI may contain **hallucinated or incorrect information**. Please **verify before using**.  

All rights reserved. For permissions or commercial licensing, contact: [info@quantuniversity.com](mailto:info@quantuniversity.com)
