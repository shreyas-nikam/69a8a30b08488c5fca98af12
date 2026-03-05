import matplotlib
matplotlib.use('Agg')

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import json
import os
import uuid
from source import *

st.set_page_config(page_title="QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone")
st.divider()

def apply_typography():
    st.markdown(
        """
        <style>
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }
        </style>
        """, unsafe_allow_html=True
    )

apply_typography()

# Session State Initialization
st.session_state.setdefault("system_type", "LLM")
st.session_state.setdefault("system_name", "Corporate AI System v1")
st.session_state.setdefault("test_bank", [])
st.session_state.setdefault("test_results", [])
st.session_state.setdefault("findings_summary", {})
st.session_state.setdefault("run_summary", {})
st.session_state.setdefault("run_id", "")
st.session_state.setdefault("selected_instance_idx", 0)

@st.cache_data
def fetch_synthetic_bank(sys_type):
    return get_synthetic_test_bank(sys_type)

pages = [
    "1. System Configuration",
    "2. Test Bank Editor",
    "3. Security Execution",
    "4. Findings Dashboard",
    "5. Export & Audit"
]
choice = st.sidebar.selectbox("Navigation", pages)

if choice == "1. System Configuration":
    st.header("1. System Configuration")
    st.markdown("**Attack Surface Definition**: The first step in security testing is defining the 'Attack Surface.' LLMs are exposed via unstructured text (Prompt Interface), while ML APIs are exposed via structured feature vectors.")
    
    new_sys_type = st.selectbox("Select System Type", ["LLM", "ML_API"], index=0 if st.session_state.system_type == "LLM" else 1)
    sys_name = st.text_input("AI System Name", st.session_state.system_name)
    
    if new_sys_type != st.session_state.system_type:
        st.session_state.system_type = new_sys_type
        st.session_state.test_results = []
        st.session_state.findings_summary = {}
        st.session_state.run_summary = {}
        st.session_state.test_bank = fetch_synthetic_bank(new_sys_type)
        st.warning(f"System type changed to {new_sys_type}. Results cleared and test bank reset.")
    
    st.session_state.system_name = sys_name
    
    if not st.session_state.test_bank:
        st.session_state.test_bank = fetch_synthetic_bank(st.session_state.system_type)

elif choice == "2. Test Bank Editor":
    st.header("2. Test Bank Editor")
    st.markdown("**Threat Taxonomy**: Each test case is mapped to a specific risk like 'Data Leakage' to ensure coverage across the OWASP Top 10 for LLMs.")
    
    st.subheader("Upload Test Bank")
    uploaded_file = st.file_uploader("Upload Test Bank (JSON)", type=["json"])
    if uploaded_file is not None:
        try:
            data = json.load(uploaded_file)
            if not isinstance(data, list):
                raise ValueError("Uploaded JSON must be a list of test cases.")
            for tc in data:
                validate_test_case(tc)
            st.success("Valid Schema: All required keys present.")
            st.session_state.test_bank = data
        except Exception as e:
            st.error(f"Schema Mismatch: {str(e)}")
            st.stop()

    if st.button("Reset to Defaults"):
        st.session_state.test_bank = fetch_synthetic_bank(st.session_state.system_type)
        st.success("Test bank reset to synthetic defaults.")
        st.rerun()

    st.subheader("Edit Test Cases")
    
    df = pd.DataFrame(st.session_state.test_bank)
    if st.session_state.system_type == "ML_API":
        if 'test_input' in df.columns:
            df['test_input'] = df['test_input'].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)
        if 'expected_safe_behavior' in df.columns:
            df['expected_safe_behavior'] = df['expected_safe_behavior'].apply(lambda x: json.dumps(x) if isinstance(x, dict) else x)

    edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True)
    
    if st.button("Save Test Bank"):
        try:
            new_bank = []
            for _, row in edited_df.iterrows():
                test_case = row.dropna().to_dict()
                if st.session_state.system_type == "ML_API":
                    if isinstance(test_case.get('test_input'), str):
                        test_case['test_input'] = json.loads(test_case['test_input'])
                    if isinstance(test_case.get('expected_safe_behavior'), str):
                        test_case['expected_safe_behavior'] = json.loads(test_case['expected_safe_behavior'])
                
                validate_test_case(test_case)
                new_bank.append(test_case)
            
            ids = [tc.get('test_id') for tc in new_bank if 'test_id' in tc]
            if len(ids) != len(set(ids)):
                st.error("Duplicate test_ids found. Please ensure all test_ids are unique.")
            else:
                st.session_state.test_bank = new_bank
                st.session_state.test_results = []
                st.session_state.findings_summary = {}
                st.session_state.run_summary = {}
                st.success("Test bank saved successfully.")
        except json.JSONDecodeError:
            st.error("Invalid JSON format in dict fields. Ensure strings are properly formatted JSON.")
        except Exception as e:
            st.error(f"Validation Error: {str(e)}")

elif choice == "3. Security Execution":
    st.header("3. Security Execution")
    st.markdown("**Detection Engine**: For LLMs, we use Heuristic Detection (Regex strings). For ML APIs, we use Perturbation Testing (testing how the model reacts to out-of-range values like `age: -10`).")
    
    if not st.session_state.test_bank:
        st.warning("Test bank is empty. Please configure tests in the Test Bank Editor.")
    else:
        st.info(f"Ready to execute {len(st.session_state.test_bank)} tests for {st.session_state.system_type}.")
        
        if st.button("Run Assessment"):
            st.session_state.run_id = str(uuid.uuid4())
            
            with st.spinner("Executing Security Tests..."):
                results = execute_security_tests(st.session_state.test_bank, st.session_state.system_type)
                summary = classify_and_summarize_findings(results)
                
                st.session_state.test_results = results
                st.session_state.findings_summary = summary
                st.session_state.run_summary = summary
                
            st.success("Assessment Completed!")

elif choice == "4. Findings Dashboard":
    st.header("4. Findings Dashboard")
    st.markdown("**Risk Aggregation**: Not all failures are equal; a 'Critical' failure in Data Leakage represents a higher business risk than a 'Low' severity failure in Input Evasion.")
    
    if not st.session_state.test_results:
        st.warning("No test results found. Please run the assessment in the Security Execution page.")
    else:
        summary = st.session_state.findings_summary
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Tests", summary.get("total_tests", 0))
        col2.metric("Passed", summary.get("passed", 0))
        col3.metric("Failed", summary.get("failed", 0))
        
        st.subheader("Failures by Severity")
        failures = summary.get("failures_by_severity", {})
        if failures:
            fig, ax = plt.subplots()
            ax.bar(failures.keys(), failures.values(), color=['#FF9999', '#FF4C4C', '#FF0000', '#8B0000'])
            ax.set_ylabel("Count")
            ax.set_title("Failed Tests per Severity")
            st.pyplot(fig, use_container_width=True)
        else:
            st.info("No failures to display! Perfect score.")
        
        st.subheader("Detailed Failure Breakdown")
        failed_tests = [res for res in st.session_state.test_results if not res.get("passed", True)]
        if failed_tests:
            st.dataframe(pd.DataFrame(failed_tests), use_container_width=True)
        else:
            st.success("All tests passed.")

elif choice == "5. Export & Audit":
    st.header("5. Export & Audit")
    st.markdown("**Chain of Custody**: In regulated AI environments, security tests must be reproducible and hashed to prove that findings haven't been tampered with post-assessment.")
    
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    
    idx = st.session_state.get("selected_instance_idx", 0)
    
    if not st.session_state.test_results:
        st.warning("No results available to export. Run an assessment first.")
    else:
        if st.button("Generate Artifacts"):
            with st.spinner("Generating Cryptographic Manifest..."):
                report = generate_executive_summary_report(
                    st.session_state.findings_summary,
                    st.session_state.system_type,
                    st.session_state.system_name,
                    st.session_state.run_id
                )
                
                artifacts = {
                    "test_results.json": json.dumps(st.session_state.test_results, indent=2),
                    "findings_summary.json": json.dumps(st.session_state.findings_summary, indent=2),
                    "executive_summary.md": report
                }
                
                out_dir = "reports"
                os.makedirs(out_dir, exist_ok=True)
                
                try:
                    manifest = export_artifacts(artifacts, out_dir)
                    st.success("Artifacts generated and verified successfully!")
                    
                    st.subheader("Evidence Manifest")
                    st.code(json.dumps(manifest, indent=2), language='json')
                    
                    st.subheader("Download Artifacts")
                    st.download_button("Download Test Results (JSON)", data=artifacts["test_results.json"], file_name="test_results.json")
                    st.download_button("Download Summary (JSON)", data=artifacts["findings_summary.json"], file_name="findings_summary.json")
                    st.download_button("Download Executive Summary (MD)", data=artifacts["executive_summary.md"], file_name="executive_summary.md")
                    st.download_button("Download Evidence Manifest (JSON)", data=json.dumps(manifest, indent=2), file_name="evidence_manifest.json")
                    
                except Exception as e:
                    st.error(f"Failed to write artifacts to directory: {e}")
                    st.warning("Providing direct download links as fallback:")
                    st.download_button("Download Test Results (JSON)", data=artifacts["test_results.json"], file_name="test_results.json")
                    st.download_button("Download Summary (JSON)", data=artifacts["findings_summary.json"], file_name="findings_summary.json")
                    st.download_button("Download Executive Summary (MD)", data=artifacts["executive_summary.md"], file_name="executive_summary.md")
