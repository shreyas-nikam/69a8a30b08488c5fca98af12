import pytest
from streamlit.testing.v1 import AppTest
import source
import json
import pandas as pd
import tempfile
import os

# Helper to create a temporary JSON file for testing uploads
def create_temp_test_bank(data):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
    json.dump(data, tmp)
    tmp.close()
    return tmp.name

def test_app_smoke_load():
    """Requirement 1: App loads without error."""
    at = AppTest.from_file("app.py", default_timeout=30)
    at.run()
    assert not at.exception
    assert at.title[0].value == "QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone"

def test_gate_checks_navigation():
    """Requirement 4: Fallback/Gate tests. App must block forward steps if prerequisites are missing."""
    at = AppTest.from_file("app.py")
    at.run()
    
    # Navigate to Execution Engine without loading a test bank
    at.sidebar.selectbox("Navigation").select("3. Execution Engine").run()
    # App should show a warning and stop
    assert any("Please define or load a Test Bank" in w.value for w in at.warning)
    
    # Navigate to Findings without execution
    at.sidebar.selectbox("Navigation").select("4. Findings Dashboard").run()
    assert any("Please define or load a Test Bank" in w.value for w in at.warning)

def test_schema_validation_drift():
    """Requirement 2: Upload logic for invalid/empty/malformed JSON."""
    at = AppTest.from_file("app.py")
    at.sidebar.selectbox("Navigation").select("2. Test Bank Editor").run()
    
    # 1. Test empty bank
    empty_bank_path = create_temp_test_bank([])
    try:
        with open(empty_bank_path, "rb") as f:
            at.file_uploader(label="Upload Custom Test Bank (.json)").upload(f).run()
        assert any("Uploaded test bank contains zero entries." in e.value for e in at.error)
    finally:
        os.unlink(empty_bank_path)

    # 2. Test malformed JSON
    malformed_path = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
    malformed_path.write("{ 'broken': json }")
    malformed_path.close()
    try:
        with open(malformed_path.name, "rb") as f:
            at.file_uploader(label="Upload Custom Test Bank (.json)").upload(f).run()
        assert any("Invalid JSON file format." in e.value for e in at.error)
    finally:
        os.unlink(malformed_path.name)

def test_equivalence_source_vs_app():
    """Requirement 3: Compare source logic outputs with App state."""
    at = AppTest.from_file("app.py")
    
    # Path: System Config (LLM) -> Test Bank Editor -> Load Standard
    at.sidebar.selectbox("System Type").set_value("LLM").run()
    at.sidebar.selectbox("Navigation").select("2. Test Bank Editor").run()
    at.button("Load Standard Test Bank").click().run()
    
    # Get reference from source directly
    llm_ref, _ = source.generate_synthetic_test_banks()
    
    # Assert App state matches source function output
    app_bank = at.session_state["test_bank"]
    assert len(app_bank) == len(llm_ref)
    assert app_bank[0]["test_id"] == llm_ref[0]["test_id"]

    # Run Execution
    at.sidebar.selectbox("Navigation").select("3. Execution Engine").run()
    at.button("Run Security Evaluation").click().run()
    
    app_results = at.session_state["execution_results"]
    
    # Equivalence: Execute using source directly and compare
    # Note: source.execute_security_tests takes (test_bank, mock_func, system_type)
    mock_func = source.get_mocked_ai_system("LLM")
    ref_results = source.execute_security_tests(llm_ref, mock_func, "LLM")
    
    assert len(app_results) == len(ref_results)
    # Check if first item result keys match
    assert set(app_results[0].keys()) == set(ref_results[0].keys())

def test_export_manifest_and_audit():
    """Requirement 5: Trigger export and verify manifest contents."""
    at = AppTest.from_file("app.py")
    
    # Setup data first to satisfy gates
    at.sidebar.selectbox("Navigation").select("2. Test Bank Editor").run()
    at.button("Load Standard Test Bank").click().run()
    at.sidebar.selectbox("Navigation").select("3. Execution Engine").run()
    at.button("Run Security Evaluation").click().run()
    
    # Go to Export & Audit
    at.sidebar.selectbox("Navigation").select("5. Export & Audit").run()
    at.button("Generate Audit Bundle").click().run()
    
    assert "Audit Bundle and Manifest Generated Successfully." in at.success[0].value
    
    # Verify Manifest structure in session state
    manifest = at.session_state["audit_manifest"]
    assert "run_id" in manifest
    assert "timestamp" in manifest
    assert "artifacts" in manifest
    
    # Check that individual file hashes exist in the manifest
    artifacts = manifest["artifacts"]
    assert "test_bank" in artifacts
    assert "test_results" in artifacts
    assert "sha256" in artifacts["test_bank"]

    # Verify Download Buttons are rendered
    assert any("Download Executive Summary" in b.label for b in at.download_button)
    assert any("Download JSON Artifact Bundle" in b.label for b in at.download_button)

def test_system_type_reset_logic():
    """Verify that switching system type resets the test bank as per app code."""
    at = AppTest.from_file("app.py")
    at.run()
    
    # 1. Load LLM data
    at.sidebar.selectbox("System Type").set_value("LLM").run()
    at.sidebar.selectbox("Navigation").select("2. Test Bank Editor").run()
    at.button("Load Standard Test Bank").click().run()
    assert len(at.session_state["test_bank"]) > 0
    
    # 2. Switch to ML_API
    at.sidebar.selectbox("System Type").set_value("ML_API").run()
    # State should be reset
    assert at.session_state["test_bank"] == []
    assert at.session_state["execution_results"] is None

def test_findings_dashboard_metrics():
    """Verify Findings Dashboard displays correct summary values."""
    at = AppTest.from_file("app.py")
    
    # Setup
    at.sidebar.selectbox("Navigation").select("2. Test Bank Editor").run()
    at.button("Load Standard Test Bank").click().run()
    at.sidebar.selectbox("Navigation").select("3. Execution Engine").run()
    at.button("Run Security Evaluation").click().run()
    
    # Navigate to Dashboard
    at.sidebar.selectbox("Navigation").select("4. Findings Dashboard").run()
    
    findings = at.session_state["findings"]
    
    # Metric check
    # at.metric returns a list of metric widgets. Labels must match app.py exactly.
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Total Tests Executed"] == str(findings["total_tests"])
    assert metrics["Total Fails"] == str(findings["total_fail"])
    assert metrics["Critical Vulnerabilities"] == str(len(findings["critical_failures"]))

    # Visual check: If failures exist, error box should show
    if findings["critical_failures"]:
        assert any("Critical Vulnerability/Vulnerabilities Detected!" in e.value for e in at.error)