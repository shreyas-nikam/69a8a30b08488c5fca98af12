import matplotlib
matplotlib.use('Agg')

import streamlit as st
import pandas as pd
import os
import time
import json

# MUST: Import business logic without module-level attribute assignment
from source import *

# Initialize page config
st.set_page_config(page_title="QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone", layout="wide")

# Enforce Typography System
def apply_typography():
    # Uses .streamlit/config.toml for Inter font styling
    st.markdown("""
    <style>
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }
    </style>
    """, unsafe_allow_html=True)

apply_typography()

# Sidebar Navigation & Branding
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone")
st.divider()

# Fallback for globals if not in source.py
try:
    threat_cats = THREAT_CATEGORIES
except NameError:
    threat_cats = ["Prompt Injection", "Data Leakage", "Model Inversion", "Denial of Service", "Jailbreak"]

try:
    sev_levels = SEVERITY_LEVELS
except NameError:
    sev_levels = ["Low", "Medium", "High", "Critical"]

# Initialize Session State Variables cleanly
st.session_state.setdefault("system_type", "LLM")
st.session_state.setdefault("test_bank", [])
st.session_state.setdefault("execution_results", [])
st.session_state.setdefault("findings_summary", {})
st.session_state.setdefault("artifact_manifest", [])
st.session_state.setdefault("run_id", f"RUN_{int(time.time())}")
st.session_state.setdefault("current_report_dir", os.path.join("reports", st.session_state.run_id))
st.session_state.setdefault("selected_instance_idx", 0)

# Navigation MUST strictly use sidebar selectbox
nav_options = [
    "1. System Configuration",
    "2. Test Bank Editor",
    "3. Execution Engine",
    "4. Findings Dashboard",
    "5. Audit & Export"
]
selected_stage = st.sidebar.selectbox("Workflow Stage", nav_options)

# --- Page 1: System Configuration ---
if selected_stage == "1. System Configuration":
    st.header("System Configuration")
    st.markdown("**Role:** Security Engineer")
    st.markdown("**Goal:** Build a threat-driven test bank and operationalize testing for AI Systems. Select your target system architecture below to initialize the session.")
    
    current_index = 0 if st.session_state.system_type == "LLM" else 1
    new_sys_type = st.radio("Select AI System Type:", ["LLM", "ML_API"], index=current_index)
    
    if new_sys_type != st.session_state.system_type:
        # Clear downstream data on system change to maintain state integrity
        st.session_state.system_type = new_sys_type
        st.session_state.test_bank = []
        st.session_state.execution_results = []
        st.session_state.findings_summary = {}
        st.rerun()

# --- Page 2: Test Bank Editor ---
elif selected_stage == "2. Test Bank Editor":
    st.header("Test Bank Editor")
    st.markdown("Author structural test cases or load industry-standard baselines. Each test requires an ID, Category, Input, Expected Behavior, and Severity definition.")
    
    if st.button("Load Industry Standard Samples"):
        with st.spinner("Loading standard baseline test cases..."):
            try:
                # Generate dummy artifact as specified, then load bank
                os.makedirs("tmp", exist_ok=True)
                save_json_artifact([{"sample": "data"}], "sample_init.json", "tmp")
                
                samples = load_test_bank(st.session_state.system_type)
                if isinstance(samples, list):
                    st.session_state.test_bank.extend(samples)
                    st.success("Industry samples loaded successfully.")
                else:
                    st.error("Loaded test bank is not in expected list format.")
            except Exception as e:
                st.error(f"Failed to load samples: {e}")
                
    st.subheader("Add Custom Test Case")
    with st.form("test_case_form"):
        t_id = st.text_input("Test ID (e.g., TC-001)")
        t_category = st.selectbox("Threat Category", threat_cats)
        t_input = st.text_area("Test Input (Enter prompt for LLM or JSON string for ML API)")
        t_behavior = st.text_area("Expected Safe Behavior")
        t_severity = st.selectbox("Severity Level", sev_levels)
        
        if st.form_submit_button("Add Test Case"):
            if not t_id or not t_input:
                st.error("Test ID and Test Input are required.")
                st.stop()
            
            try:
                new_case = create_test_case(
                    test_id=t_id,
                    threat_category=t_category,
                    test_input=t_input,
                    expected_safe_behavior=t_behavior,
                    severity_level=t_severity
                )
                st.session_state.test_bank.append(new_case)
                st.success(f"Test Case '{t_id}' appended to test bank.")
            except Exception as e:
                st.error(f"Validation/Creation Error: {e}")
                
    st.subheader("Current Test Bank")
    if st.session_state.test_bank:
        st.dataframe(pd.DataFrame(st.session_state.test_bank), use_container_width=True)
    else:
        st.info("Test bank is currently empty.")

# --- Page 3: Execution Engine ---
elif selected_stage == "3. Execution Engine":
    st.header("Deterministic Execution Engine")
    if len(st.session_state.test_bank) == 0:
        st.warning("Your test bank is empty. Please author or load test cases in the Test Bank Editor.")
    else:
        st.markdown("**Execution Logic:** Runs deterministic checks against AI mock interfaces. LLMs utilize heuristic (keyword block) checks; ML APIs use perturbation (range/type) checks.")
        
        if st.button("Execute Security Tests"):
            with st.spinner("Executing test bank against mocked AI system..."):
                try:
                    mock_system = get_mocked_ai_system(st.session_state.system_type)
                    results = execute_security_tests(st.session_state.test_bank, mock_system)
                    st.session_state.execution_results = results
                    st.success("Execution completed!")
                except Exception as e:
                    st.error(f"Execution Engine Failure: {e}")
                    
        if st.session_state.execution_results:
            st.subheader("Execution Results")
            results_df = pd.DataFrame(st.session_state.execution_results)
            st.dataframe(results_df, use_container_width=True)
            
            st.subheader("Result Details")
            for res in st.session_state.execution_results:
                # Display visual cues based on status
                res_status = str(res.get("test_result", "")).upper()
                msg = f"**{res.get('test_id', 'Unknown')}** - {res.get('notes', 'No notes provided.')}"
                if res_status == "PASS":
                    st.success(msg)
                else:
                    st.error(msg)

# --- Page 4: Findings Dashboard ---
elif selected_stage == "4. Findings Dashboard":
    st.header("Findings & Risk Dashboard")
    if not st.session_state.execution_results:
        st.warning("No execution results found. Please run tests in the Execution Engine first.")
    else:
        with st.spinner("Aggregating findings..."):
            try:
                summary = classify_and_summarize_findings(st.session_state.execution_results)
                st.session_state.findings_summary = summary
            except Exception as e:
                st.error(f"Failed to summarize findings: {e}")
                summary = {}
        
        if summary:
            crit_fails = summary.get("critical_failures", [])
            if crit_fails:
                st.warning(f"🚨 CRITICAL FAILURES DETECTED: {', '.join(crit_fails)}")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Tests", summary.get("total_tests", 0))
            col2.metric("Total Fails", summary.get("total_fails", 0))
            col3.metric("Critical Fails", len(crit_fails))
            
            st.subheader("Failure Distribution")
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                st.markdown("**Failures by Severity**")
                sev_data = summary.get("failures_by_severity", {})
                if sev_data:
                    st.bar_chart(pd.Series(sev_data))
                else:
                    st.info("No severity data available.")
                    
            with chart_col2:
                st.markdown("**Failures by Threat Category**")
                cat_data = summary.get("failures_by_category", {})
                if cat_data:
                    st.bar_chart(pd.Series(cat_data))
                else:
                    st.info("No category data available.")

# --- Page 5: Audit & Export ---
elif selected_stage == "5. Audit & Export":
    st.header("Audit & Export")
    st.markdown("Generate cryptographic forensic integrity bundles for compliance reviews.")
    st.markdown(r"$$ H = \text{SHA256}(\text{File Content}) $$")
    st.markdown(r"where $H$ is the 256-bit cryptographic hash used to verify that the assessment evidence has not been tampered with.")
    
    if not st.session_state.findings_summary:
        st.warning("No findings to export. Please view the Findings Dashboard to generate metrics.")
    else:
        if st.button("Generate Audit Bundle"):
            with st.spinner("Bundling artifacts and computing SHA-256 hashes..."):
                try:
                    out_dir = st.session_state.current_report_dir
                    os.makedirs(out_dir, exist_ok=True)
                    
                    # Generate executive summary content
                    exec_summary_content = generate_executive_summary_report(
                        st.session_state.findings_summary,
                        st.session_state.system_type
                    )
                    
                    # Fulfill constraint: MUST use idx from session state for export manifest metadata
                    idx = st.session_state.get("selected_instance_idx", 0)
                    meta_data = {"export_instance_idx": idx, "run_id": st.session_state.run_id}
                    
                    # Save artifacts
                    path_json = save_json_artifact(st.session_state.execution_results, "execution_results.json", out_dir)
                    path_meta = save_json_artifact(meta_data, "export_metadata.json", out_dir)
                    path_md = save_markdown_artifact(exec_summary_content, "executive_summary.md", out_dir)
                    
                    # Generate Manifest Hashes
                    manifest_list = []
                    for fpath in [path_json, path_meta, path_md]:
                        if fpath and os.path.exists(fpath):
                            file_hash = generate_sha256_hash(fpath)
                            manifest_list.append({
                                "Artifact Filename": os.path.basename(fpath),
                                "Relative Path": fpath,
                                "SHA-256 Hash": file_hash
                            })
                            
                    # Save manifest itself
                    manifest_path = save_json_artifact(manifest_list, "evidence_manifest.json", out_dir)
                    if manifest_path and os.path.exists(manifest_path):
                         manifest_list.append({
                             "Artifact Filename": "evidence_manifest.json",
                             "Relative Path": manifest_path,
                             "SHA-256 Hash": generate_sha256_hash(manifest_path)
                         })
                    
                    st.session_state.artifact_manifest = manifest_list
                    st.session_state.executive_summary_cache = exec_summary_content
                    st.success("Audit bundle generated successfully!")
                    
                except Exception as e:
                    st.error(f"Export failed: {e}")
                    
        if st.session_state.artifact_manifest:
            st.subheader("Evidence Manifest")
            st.dataframe(pd.DataFrame(st.session_state.artifact_manifest), use_container_width=True)
            
            if "executive_summary_cache" in st.session_state:
                st.subheader("Executive Summary Preview")
                st.markdown(st.session_state.executive_summary_cache)
