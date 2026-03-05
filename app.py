import matplotlib
matplotlib.use("Agg")
import streamlit as st
from source import *
import pandas as pd
import json
import datetime
import os
import tempfile

st.set_page_config(page_title="QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone")
st.divider()

# State Initialization
st.session_state.setdefault("test_bank", [])
st.session_state.setdefault("execution_results", None)
st.session_state.setdefault("findings", None)
st.session_state.setdefault("run_id", datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
st.session_state.setdefault("system_type", "LLM")
st.session_state.setdefault("system_name", "Enterprise Chatbot")

def apply_typography():
    st.markdown("""
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
    </style>
    """, unsafe_allow_html=True)
apply_typography()

# Navigation
pages = [
    "1. System Configuration",
    "2. Test Bank Editor",
    "3. Execution Engine",
    "4. Findings Dashboard",
    "5. Export & Audit"
]
selected_page = st.sidebar.selectbox("Navigation", options=pages, index=0)

st.sidebar.divider()
st.sidebar.markdown(f"### System Configuration")

def reset_state():
    st.session_state.test_bank = []
    st.session_state.execution_results = None
    st.session_state.findings = None

new_system_type = st.sidebar.selectbox(
    "System Type",
    options=["LLM", "ML_API"],
    index=0 if st.session_state.system_type == "LLM" else 1
)

if new_system_type != st.session_state.system_type:
    st.session_state.system_type = new_system_type
    reset_state()

st.session_state.system_name = st.sidebar.text_input("System Name", value=st.session_state.system_name)

# Helper for Gate checks
def check_gate_2():
    if not st.session_state.test_bank:
        st.warning("Please define or load a Test Bank in the 'Test Bank Editor' to proceed.")
        st.stop()

def check_gate_3():
    if not st.session_state.execution_results:
        st.warning("Please execute tests in the 'Execution Engine' to proceed.")
        st.stop()

@st.cache_data
def cached_generate_synthetic_test_banks():
    return generate_synthetic_test_banks()

@st.cache_data
def cached_execute_security_tests(test_bank_json: str, system_type: str):
    tb = json.loads(test_bank_json)
    mock_func = get_mocked_ai_system(system_type)
    return execute_security_tests(tb, mock_func, system_type)

# --- Page Routing ---

if selected_page == "1. System Configuration":
    st.markdown(f"{MARKDOWN['intro']}")
    st.markdown(f"{MARKDOWN['defining_system']}")
    st.markdown(f"{MARKDOWN['mock_explanation']}")

elif selected_page == "2. Test Bank Editor":
    st.markdown(f"{MARKDOWN['crafting_test_bank']}")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Load Standard Test Bank"):
            llm_bank, ml_bank = cached_generate_synthetic_test_banks()
            st.session_state.test_bank = llm_bank if st.session_state.system_type == "LLM" else ml_bank
            st.success(f"Loaded standard {st.session_state.system_type} test bank!")
            st.rerun()
            
    with col2:
        uploaded_file = st.file_uploader("Upload Custom Test Bank (.json)", type=["json"])
        if uploaded_file is not None:
            if uploaded_file.size > 5 * 1024 * 1024:
                st.error("File size exceeds 5MB limit.")
            else:
                try:
                    custom_bank = json.load(uploaded_file)
                    if len(custom_bank) == 0:
                        st.error("Uploaded test bank contains zero entries.")
                    else:
                        validate_test_bank(custom_bank)
                        st.session_state.test_bank = custom_bank
                        st.success("Custom test bank uploaded and validated successfully!")
                except json.JSONDecodeError:
                    st.error("Invalid JSON file format.")
                except Exception as e:
                    st.error(f"Validation Error: {str(e)}")
                    
    if st.session_state.test_bank:
        st.markdown(f"### Data Inspector: {st.session_state.system_type} Test Bank")
        edited_df = st.data_editor(
            pd.DataFrame(st.session_state.test_bank),
            use_container_width=True,
            num_rows="dynamic"
        )
        if st.button("Save Edits & Re-Validate"):
            try:
                edited_bank = edited_df.to_dict(orient="records")
                # Re-parse stringified dicts from Streamlit data editor if applicable
                for item in edited_bank:
                    if isinstance(item.get("test_input"), str) and st.session_state.system_type == "ML_API":
                        try:
                            item["test_input"] = json.loads(item["test_input"].replace("'", "\""))
                        except: pass
                    if isinstance(item.get("expected_safe_behavior"), str) and st.session_state.system_type == "ML_API":
                        try:
                            item["expected_safe_behavior"] = json.loads(item["expected_safe_behavior"].replace("'", "\""))
                        except: pass

                validate_test_bank(edited_bank)
                st.session_state.test_bank = edited_bank
                st.success("Changes saved and validated!")
            except Exception as e:
                st.error(f"Validation Error during save: {str(e)}")

    st.markdown(f"{MARKDOWN['test_bank_explanation']}")

elif selected_page == "3. Execution Engine":
    check_gate_2()
    st.markdown(f"{MARKDOWN['executing_tests']}")
    
    st.markdown(r"""$$
    \text{output} \supseteq \text{expected\_safe\_behavior} \quad \text{or} \quad \text{output} \not\ni \text{sensitive\_keyword}
    $$""")
    st.markdown(r"where $\supseteq$ represents substring matching or heuristic pattern containment.")
    
    if st.button("Run Security Evaluation", type="primary"):
        with st.spinner("Running deterministic security probes..."):
            tb_json = json.dumps(st.session_state.test_bank)
            results = cached_execute_security_tests(tb_json, st.session_state.system_type)
            st.session_state.execution_results = results
            st.session_state.findings = classify_and_summarize_findings(results)
        st.success("Execution completed successfully.")
        
    if st.session_state.execution_results:
        st.dataframe(pd.DataFrame(st.session_state.execution_results), use_container_width=True)
        
    st.markdown(f"{MARKDOWN['execution_explanation']}")

elif selected_page == "4. Findings Dashboard":
    check_gate_2()
    check_gate_3()
    st.markdown(f"{MARKDOWN['classifying_findings']}")
    
    findings = st.session_state.findings
    if findings:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Tests Executed", findings["total_tests"])
        col2.metric("Total Fails", findings["total_fail"])
        col3.metric("Critical Vulnerabilities", len(findings["critical_failures"]))
        
        if findings["critical_failures"]:
            st.error(f"⚠️ {len(findings['critical_failures'])} Critical Vulnerability/Vulnerabilities Detected!")
            for crit in findings["critical_failures"]:
                st.error(f"**Test ID:** {crit['test_id']} | **Threat:** {crit['threat_category']} | **Notes:** {crit['notes']}")
                
        st.markdown(f"### Failure Distributions")
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.markdown(f"**By Threat Category**")
            df_threats = pd.DataFrame(list(findings["failures_by_threat_category"].items()), columns=["Threat Category", "Count"])
            st.bar_chart(df_threats.set_index("Threat Category"), use_container_width=True)
            
        with col_chart2:
            st.markdown(f"**By Severity Level**")
            df_severity = pd.DataFrame(list(findings["failures_by_severity"].items()), columns=["Severity", "Count"])
            st.bar_chart(df_severity.set_index("Severity"), use_container_width=True)
            
        st.markdown(f"### Detailed Execution Results Table")
        st.dataframe(pd.DataFrame(st.session_state.execution_results), use_container_width=True)
        
    st.markdown(f"{MARKDOWN['classification_explanation']}")

elif selected_page == "5. Export & Audit":
    check_gate_2()
    check_gate_3()
    st.markdown(f"{MARKDOWN['audit_artifacts']}")
    
    st.markdown(r"""$$
    H = \text{SHA256}(\text{File Content})
    $$""")
    st.markdown(r"where $H$ is the 256-bit cryptographic fingerprint ensuring forensic integrity.")
    
    if st.button("Generate Audit Bundle", type="primary"):
        with st.spinner("Calculating SHA-256 integrity hashes..."):
            temp_dir = tempfile.mkdtemp()
            
            report_md = generate_executive_summary_report(
                findings_summary=st.session_state.findings,
                system_type=st.session_state.system_type,
                system_name=st.session_state.system_name,
                run_id=st.session_state.run_id
            )
            
            bank_path = save_json_artifact(st.session_state.test_bank, temp_dir, "security_test_bank.json")
            results_path = save_json_artifact(st.session_state.execution_results, temp_dir, "test_execution_results.json")
            findings_path = save_json_artifact(st.session_state.findings, temp_dir, "findings_summary.json")
            report_path = save_markdown_artifact(report_md, temp_dir, "session07_executive_summary.md")
            
            artifacts_map = {
                "test_bank": bank_path,
                "test_results": results_path,
                "findings_summary": findings_path,
                "executive_report": report_path
            }
            
            manifest = export_artifacts(artifacts_map, temp_dir, st.session_state.run_id)
            
            st.session_state.audit_manifest = manifest
            st.session_state.audit_report_md = report_md
            
        st.success("Audit Bundle and Manifest Generated Successfully.")
        
    if "audit_manifest" in st.session_state:
        with st.expander("View Evidence Manifest", expanded=True):
            st.json(st.session_state.audit_manifest)
            
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Download Executive Summary (.md)",
                data=st.session_state.audit_report_md,
                file_name="session07_executive_summary.md",
                mime="text/markdown",
                use_container_width=True
            )
        with col2:
            bundle_data = {
                "manifest": st.session_state.audit_manifest,
                "findings": st.session_state.findings
            }
            st.download_button(
                label="Download JSON Artifact Bundle",
                data=json.dumps(bundle_data, indent=2),
                file_name="audit_artifacts_bundle.json",
                mime="application/json",
                use_container_width=True
            )
            
    st.markdown(f"{MARKDOWN['audit_explanation']}")


# License
st.caption('''
---
## QuantUniversity License

© QuantUniversity 2025  
This notebook was created for **educational purposes only** and is **not intended for commercial use**.  

- You **may not copy, share, or redistribute** this notebook **without explicit permission** from QuantUniversity.  
- You **may not delete or modify this license cell** without authorization.  
- This notebook was generated using **QuCreate**, an AI-powered assistant.  
- Content generated by AI may contain **hallucinated or incorrect information**. Please **verify before using**.  

All rights reserved. For permissions or commercial licensing, contact: [info@quantuniversity.com](mailto:info@quantuniversity.com)
''')
