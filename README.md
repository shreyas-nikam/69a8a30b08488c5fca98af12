# QuLab: Adversarial & Security Test Bank Builder

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Red-critical?style=for-the-badge&logo=probot&logoColor=white)

## 📝 Project Description
**QuLab: Adversarial & Security Test Bank Builder** is a comprehensive Streamlit-based security framework designed to evaluate the robustness of Large Language Models (LLMs) and Machine Learning (ML) APIs. 

The application allows security engineers and AI developers to build a repository of adversarial prompts/inputs (a "Test Bank"), execute these tests against simulated or real environments, and generate forensic-grade audit reports. It focuses on identifying vulnerabilities such as prompt injection, data leakage, and toxic content generation.

---

## ✨ Features

- **System Profiling**: Configure the target system type (LLM or ML API) to tailor the adversarial testing strategy.
- **Dynamic Test Bank Editor**: 
    - Load industry-standard security templates.
    - Upload custom `.json` test banks.
    - Edit test cases in real-time using an interactive data grid.
- **Automated Execution Engine**: Run deterministic security probes using heuristic pattern containment to detect failures.
- **Vulnerability Dashboard**: Visualize failure distributions by threat category and severity levels using interactive charts.
- **Audit & Forensic Export**: 
    - Generate SHA-256 cryptographic fingerprints for all test artifacts.
    - Export Executive Summary reports in Markdown.
    - Download complete JSON bundles for compliance and auditing.

---

## 🛠 Technology Stack

- **Frontend/App Framework**: [Streamlit](https://streamlit.io/)
- **Data Handling**: [Pandas](https://pandas.pydata.org/)
- **Visualizations**: [Matplotlib](https://matplotlib.org/) (Agg backend), Streamlit Native Charts
- **Security Logic**: Custom logic for SHA-256 integrity hashing and heuristic evaluation.
- **Data Format**: JSON (for test banks and manifests).

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- `pip` package manager

### Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/qu-lab-security-builder.git
   cd qu-lab-security-builder
   ```

2. **Install dependencies**:
   ```bash
   pip install streamlit pandas matplotlib
   ```

3. **Required Files**:
   Ensure you have a `source.py` file in the same directory. This file should contain the backend logic including:
   - `generate_synthetic_test_banks()`
   - `execute_security_tests()`
   - `classify_and_summarize_findings()`
   - `validate_test_bank()`
   - `MARKDOWN` dictionary for UI text.

### Running the Application
```bash
streamlit run app.py
```

---

## 📖 Usage Guide

The application follows a linear 5-step workflow:

1. **System Configuration**: Define the name and type of the system under test (e.g., Enterprise Chatbot).
2. **Test Bank Editor**: Populate your test suite. You can use the "Load Standard Test Bank" button to start with common adversarial patterns.
3. **Execution Engine**: Click "Run Security Evaluation." The engine compares system outputs against `expected_safe_behavior` using the logic:
   $$\text{output} \supseteq \text{expected\_safe\_behavior} \quad \text{or} \quad \text{output} \not\ni \text{sensitive\_keyword}$$
4. **Findings Dashboard**: Review metrics on "Critical Vulnerabilities" and see which categories (e.g., Jailbreaking, PII Leakage) are most affected.
5. **Export & Audit**: Generate a forensic bundle. The system calculates a SHA-256 hash to ensure the integrity of your security audit:
   $$H = \text{SHA256}(\text{File Content})$$

---

## 📂 Project Structure

```text
├── app.py              # Main Streamlit application UI and routing
├── source.py           # Logic layer (synthetic data, execution, validation)
├── requirements.txt    # Project dependencies
└── README.md           # Project documentation
```

---

## 🤝 Contributing

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/SecurityFeature`).
3. Commit your Changes (`git commit -m 'Add some SecurityFeature'`).
4. Push to the Branch (`git push origin feature/SecurityFeature`).
5. Open a Pull Request.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ✉️ Contact

**QuantUniversity**  
Website: [www.quantuniversity.com](https://www.quantuniversity.com)  
Project Link: [https://github.com/your-username/qu-lab-security-builder](https://github.com/your-username/qu-lab-security-builder)

---
*Disclaimer: This tool is intended for ethical security testing and research purposes only. Always obtain permission before testing against production systems.*

## License

## QuantUniversity License

© QuantUniversity 2025  
This notebook was created for **educational purposes only** and is **not intended for commercial use**.  

- You **may not copy, share, or redistribute** this notebook **without explicit permission** from QuantUniversity.  
- You **may not delete or modify this license cell** without authorization.  
- This notebook was generated using **QuCreate**, an AI-powered assistant.  
- Content generated by AI may contain **hallucinated or incorrect information**. Please **verify before using**.  

All rights reserved. For permissions or commercial licensing, contact: [info@quantuniversity.com](mailto:info@quantuniversity.com)
