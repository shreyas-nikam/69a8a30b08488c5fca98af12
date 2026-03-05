import matplotlib
matplotlib.use('Agg')
import streamlit as st
from source import *

st.set_page_config(page_title="QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone")
st.divider()

import json
import tempfile
import shutil
import os
from datetime import datetime
import pandas as pd

# --- Typography ---
def apply_typography():
    st.markdown("<style>body { font-family: 'Inter', sans-serif; }</style>", unsafe_allow_html=True)

apply_typography()

# --- Determinism ---
set_global_seed(42)

# --- Session State Management ---
st.session_state.setdefault("system_type", "LLM")

@st.cache_data
def load_synthetic_banks():
    return get_synthetic_test_banks()

if "test_bank" not in st.session_state:
    st.session_state.test_bank = load_synthetic_banks()[st.session_state.system_type]

st.session_state.setdefault("results", None)
st.session_state.setdefault("summary", None)
st.session_state.setdefault("run_id", None)

# --- Sidebar Navigation ---
pages = [
    "System Configuration", 
    "Test Bank Editor", 
    "Execute Security Tests", 
    "Findings Dashboard", 
    "Audit Export"
]
page = st.sidebar.selectbox("Navigation", pages, index=0)

# --- Page Routing ---
if page == "System Configuration":
    st.header("1. System Configuration")
    st.markdown(f"**Role:** Security Engineer.\n\nDefine the Attack Surface by choosing between an LLM-based Prompt Interface or an ML Scoring API.")
    
    sys_options = ["LLM", "ML_API"]
    curr_idx = sys_options.index(st.session_state.system_type)
    
    selected_sys = st.radio("Select AI System Type", sys_options, index=curr_idx)
    if selected_sys != st.session_state.system_type:
        st.session_state.system_type = selected_sys
        st.session_state.test_bank = load_synthetic_banks()[selected_sys]
        st.session_state.results = None
        st.session_state.summary = None
        st.session_state.run_id = None
        st.rerun()

elif page == "Test Bank Editor":
    st.header("2. Test Bank Editor")
    st.markdown(f"Author or modify structured security test cases. Inline editing is supported below, or you can upload a custom JSON test bank. Valid system targets currently include: **{st.session_state.system_type}**.")
    
    uploaded_file = st.file_uploader("Upload custom security_test_bank.json", type=["json"])
    if uploaded_file is not None:
        try:
            uploaded_data = json.load(uploaded_file)
            if not isinstance(uploaded_data, list):
                st.error("Uploaded JSON must be a valid array of test case objects.")
            else:
                valid = True
                processed_data = []
                required_keys = {"test_id", "threat_category", "test_input", "expected_safe_behavior", "severity_level"}
                for i, row in enumerate(uploaded_data):
                    if not required_keys.issubset(row.keys()):
                        st.error(f"Row {i} is missing required fields: {required_keys - set(row.keys())}")
                        valid = False
                        break
                    if row["severity_level"] not in SEVERITY_LEVELS:
                        st.error(f"Row {i} has invalid severity: {row['severity_level']}")
                        valid = False
                        break
                    
                    if st.session_state.system_type == "ML_API" and isinstance(row["test_input"], str):
                        try:
                            row["test_input"] = json.loads(row["test_input"])
                        except:
                            st.warning(f"Row {i} has malformed JSON string for test_input. Marked for error handling.")
                            row["test_input"] = {"error": "malformed"}
                    processed_data.append(row)
                if valid:
                    st.session_state.test_bank = processed_data
                    st.success("Custom test bank successfully loaded and validated.")
        except json.JSONDecodeError:
            st.error("Invalid JSON file format. Failed to parse.")
            
    st.subheader("Current Test Bank")
    df = pd.DataFrame(st.session_state.test_bank)
    if st.session_state.system_type == "ML_API":
        df["test_input"] = df["test_input"].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
        df["expected_safe_behavior"] = df["expected_safe_behavior"].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
        
    edited_df = st.data_editor(df, use_container_width=True, num_rows="dynamic")
    
    if st.button("Save Changes"):
        if not edited_df["test_id"].is_unique:
            st.error("Error: `test_id` values must be strictly unique.")
        else:
            new_bank = edited_df.to_dict(orient="records")
            if st.session_state.system_type == "ML_API":
                for row in new_bank:
                    if isinstance(row["test_input"], str):
                        try: 
                            row["test_input"] = json.loads(row["test_input"])
                        except:
                            row["test_input"] = {"error": "malformed string override"}
                    if isinstance(row["expected_safe_behavior"], str):
                        try:
                            row["expected_safe_behavior"] = json.loads(row["expected_safe_behavior"])
                        except:
                            row["expected_safe_behavior"] = {"status": "error"}
            st.session_state.test_bank = new_bank
            st.session_state.results = None
            st.success("Changes successfully saved to the active session test bank!")

elif page == "Execute Security Tests":
    st.header("3. Execute Security Tests")
    st.markdown(f"Trigger the deterministic evaluation engine. This simulates a 'Safe Harbor' testing environment probing the **{st.session_state.system_type}** system without risking production data.")
    st.markdown(r"$$ \text{Result} = \begin{cases} \text{PASS} & \text{if } \text{Actual} \approx \text{Expected Safe Behavior} \\ \text{FAIL} & \text{otherwise} \end{cases} $$")
    
    if len(st.session_state.test_bank) == 0:
        st.warning("Active test bank is empty. Please add test cases within the Editor tab.")
    else:
        if st.button("Run Evaluation Engine"):
            with st.spinner("Executing Security Test Bank..."):
                sys_func = get_mocked_ai_system(st.session_state.system_type)
                results = execute_security_tests(st.session_state.test_bank, sys_func, st.session_state.system_type)
                st.session_state.results = results
                st.session_state.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
                st.session_state.summary = classify_and_summarize_findings(results, THREAT_CATEGORIES, SEVERITY_LEVELS)
            st.success("Test Execution Complete! Proceed to the Findings Dashboard to review system performance.")

elif page == "Findings Dashboard":
    st.header("4. Findings Dashboard")
    st.markdown(f"Review aggregated security risk metrics. A 'Critical' failure in categories like 'Prompt Injection' signifies an elevated-risk vulnerability that needs immediate remediation.")
    
    if st.session_state.results is None:
        st.info("No execution results are available. Please run tests in 'Execute Security Tests' first.")
    else:
        summary = st.session_state.summary
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Tests Evaluated", summary["total_tests"])
        pass_rate = (summary["total_pass"] / summary["total_tests"]) * 100 if summary["total_tests"] > 0 else 0
        col2.metric("System Pass Rate", f"{pass_rate:.1f}%")
        col3.metric("Critical Failures", len(summary["critical_failures"]))
        
        st.subheader("Identified Test Failures")
        failures = [r for r in st.session_state.results if r["test_result"] == "FAIL"]
        if failures:
            fail_df = pd.DataFrame(failures)
            fail_df["test_input"] = fail_df["test_input"].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
            fail_df["expected_safe_behavior"] = fail_df["expected_safe_behavior"].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
            fail_df["actual_output"] = fail_df["actual_output"].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
            
            def highlight_severity(s):
                if s["severity_level"] == "Critical": return ["background-color: #ffcccc"] * len(s)
                elif s["severity_level"] == "High": return ["background-color: #ffe6cc"] * len(s)
                return [""] * len(s)
            
            st.dataframe(fail_df.style.apply(highlight_severity, axis=1), use_container_width=True)
        else:
            st.success("All evaluated test cases PASSED! Zero vulnerabilities identified under current test constraints.")

elif page == "Audit Export":
    st.header("5. Audit Export")
    st.markdown(f"Finalize the risk assessment and generate a comprehensive security export package. Forensic integrity is maintained via rigorous cryptographic hashing.")
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    
    if st.session_state.results is None:
        st.info("No execution results detected. You must evaluate the test bank prior to exporting audit logs.")
    else:
        if st.button("Finalize Security Audit"):
            with st.spinner("Generating Cryptographic Evidence Manifest..."):
                sys_name = "Customer Support Chatbot" if st.session_state.system_type == "LLM" else "Credit Risk API"
                report_md = generate_executive_summary_report(st.session_state.summary, st.session_state.system_type, sys_name, st.session_state.run_id)
                
                artifacts_to_save = {
                    "security_test_bank.json": st.session_state.test_bank,
                    "test_execution_results.json": st.session_state.results,
                    "findings_summary.json": st.session_state.summary,
                    "executive_summary.md": report_md
                }
                
                tmp_dir = tempfile.mkdtemp()
                manifest = export_artifacts(artifacts_to_save, tmp_dir, st.session_state.run_id)
                zip_path = shutil.make_archive(os.path.join(tempfile.gettempdir(), f"audit_bundle_{st.session_state.run_id}"), 'zip', tmp_dir)
                
            with open(zip_path, "rb") as f:
                st.download_button(
                    label="Download Encapsulated Audit Bundle (ZIP)",
                    data=f,
                    file_name=f"security_audit_{st.session_state.run_id}.zip",
                    mime="application/zip"
                )
            st.success("The audit bundle has been sealed and is ready for download.")
