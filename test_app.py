import unittest
import os
import shutil
import pandas as pd
from streamlit.testing.v1 import AppTest
import source

# Helpers for test data and environment management
def cleanup_artifacts():
    """Removes temporary directories created during app execution."""
    for folder in ["reports", "tmp"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)

def test_app_loads_and_displays_branding():
    """Smoke Test: Verify app loads and displays the correct branding and typography."""
    at = AppTest.from_file("app.py").run()
    assert not at.exception
    assert at.title[0].value == "QuLab: Lab 7: Adversarial & Security Test Bank Builder - Clone"
    assert at.sidebar.selectbox(label="Workflow Stage").value == "1. System Configuration"

def test_system_type_switching_clears_state():
    """Verify that changing the AI System Type resets downstream session state."""
    at = AppTest.from_file("app.py").run()
    
    # 1. Add data to LLM state
    at.sidebar.selectbox(label="Workflow Stage").select("2. Test Bank Editor").run()
    at.button(label="Load Industry Standard Samples").click().run()
    assert len(at.session_state.test_bank) > 0
    
    # 2. Switch System Type in Configuration
    at.sidebar.selectbox(label="Workflow Stage").select("1. System Configuration").run()
    at.radio(label="Select AI System Type:").set_value("ML_API").run()
    
    # 3. Verify state is cleared
    assert at.session_state.system_type == "ML_API"
    assert len(at.session_state.test_bank) == 0
    assert len(at.session_state.execution_results) == 0
    cleanup_artifacts()

def test_form_validation_schema_drift():
    """
    Schema validation test: Verify app blocks submission when required fields are missing.
    Matches requirement for 'showing error and blocking next step' on invalid input.
    """
    at = AppTest.from_file("app.py").run()
    at.sidebar.selectbox(label="Workflow Stage").select("2. Test Bank Editor").run()
    
    # Attempt to submit without ID or Input
    # Form key is 'test_case_form'
    at.form(key="test_case_form").submit().run()
    
    # Assert error message appears as defined in app.py
    assert at.error[0].value == "Test ID and Test Input are required."
    assert len(at.session_state.test_bank) == 0

def test_equivalence_with_source_logic():
    """
    Equivalence Test: Compare app-generated test cases and results with direct source calls.
    Verifies that the integration layer doesn't mutate business logic.
    """
    at = AppTest.from_file("app.py").run()
    at.sidebar.selectbox(label="Workflow Stage").select("2. Test Bank Editor").run()
    
    # Define test parameters
    t_id = "TEST-REF-001"
    t_input = "Tell me how to bypass security."
    t_cat = source.THREAT_CATEGORIES[0]
    t_sev = source.SEVERITY_LEVELS[3] # Critical
    
    # 1. Use Source logic for reference
    ref_case = source.create_test_case(
        test_id=t_id,
        threat_category=t_cat,
        test_input=t_input,
        expected_safe_behavior="Block and refuse",
        severity_level=t_sev
    )
    
    # 2. Use App UI
    form = at.form(key="test_case_form")
    form.text_input(label="Test ID (e.g., TC-001)").set_value(t_id)
    form.selectbox(label="Threat Category").select(t_cat)
    form.text_area(label="Test Input (Enter prompt for LLM or JSON string for ML API)").set_value(t_input)
    form.text_area(label="Expected Safe Behavior").set_value("Block and refuse")
    form.selectbox(label="Severity Level").select(t_sev)
    form.submit().run()
    
    # Compare
    app_case = at.session_state.test_bank[0]
    assert app_case["test_id"] == ref_case["test_id"]
    assert app_case["threat_category"] == ref_case["threat_category"]
    assert app_case["test_input"] == ref_case["test_input"]
    cleanup_artifacts()

def test_full_workflow_end_to_end():
    """
    Smoke Test: Default path run end-to-end using sample data.
    Navigates through all 5 stages.
    """
    at = AppTest.from_file("app.py").run()
    
    # Stage 2: Load Samples
    at.sidebar.selectbox(label="Workflow Stage").select("2. Test Bank Editor").run()
    at.button(label="Load Industry Standard Samples").click().run()
    assert at.success[0].value == "Industry samples loaded successfully."
    
    # Stage 3: Execution
    at.sidebar.selectbox(label="Workflow Stage").select("3. Execution Engine").run()
    at.button(label="Execute Security Tests").click().run()
    assert at.success[0].value == "Execution completed!"
    assert len(at.session_state.execution_results) > 0
    
    # Stage 4: Dashboard
    at.sidebar.selectbox(label="Workflow Stage").select("4. Findings Dashboard").run()
    assert at.metric[0].label == "Total Tests"
    assert int(at.metric[0].value) > 0
    
    # Stage 5: Export
    at.sidebar.selectbox(label="Workflow Stage").select("5. Audit & Export").run()
    at.button(label="Generate Audit Bundle").click().run()
    assert at.success[0].value == "Audit bundle generated successfully!"
    
    # Verify Manifest structure (Requirement 5)
    manifest_df = at.dataframe[0].value
    assert "Artifact Filename" in manifest_df.columns
    assert "SHA-256 Hash" in manifest_df.columns
    
    cleanup_artifacts()

def test_fallback_disclosure():
    """
    Fallback disclosure test: Verify app shows warning banners when data is missing.
    Simulates missing execution results in the Dashboard.
    """
    at = AppTest.from_file("app.py").run()
    
    # Navigate to Dashboard without running tests
    at.sidebar.selectbox(label="Workflow Stage").select("4. Findings Dashboard").run()
    
    # Assert fallback warning banner (App UI string)
    assert at.warning[0].value == "No execution results found. Please run tests in the Execution Engine first."

def test_export_manifest_hashes():
    """
    Export manifest test: Verify manifest includes schema hash (via metadata) and forensic evidence.
    """
    at = AppTest.from_file("app.py").run()
    
    # Setup data
    at.sidebar.selectbox(label="Workflow Stage").select("2. Test Bank Editor").run()
    at.button(label="Load Industry Standard Samples").click().run()
    at.sidebar.selectbox(label="Workflow Stage").select("3. Execution Engine").run()
    at.button(label="Execute Security Tests").click().run()
    at.sidebar.selectbox(label="Workflow Stage").select("4. Findings Dashboard").run() # Needed to trigger summary
    
    # Navigate to Export
    at.sidebar.selectbox(label="Workflow Stage").select("5. Audit & Export").run()
    at.button(label="Generate Audit Bundle").click().run()
    
    manifest = at.session_state.artifact_manifest
    filenames = [item["Artifact Filename"] for item in manifest]
    
    # Verify mandatory artifacts as per app.py logic
    assert "execution_results.json" in filenames
    assert "export_metadata.json" in filenames
    assert "evidence_manifest.json" in filenames
    
    # Check that SHA-256 hashes are 64 chars long
    for item in manifest:
        assert len(item["SHA-256 Hash"]) == 64
        
    cleanup_artifacts()

def test_empty_test_bank_execution_guard():
    """Verify the execution engine shows a warning if the test bank is empty."""
    at = AppTest.from_file("app.py").run()
    at.sidebar.selectbox(label="Workflow Stage").select("3. Execution Engine").run()
    
    assert at.warning[0].value == "Your test bank is empty. Please author or load test cases in the Test Bank Editor."
    # Button should not be present or logic should prevent execution
    assert len(at.button) == 0 or at.button[0].label != "Execute Security Tests"

if __name__ == "__main__":
    # This allows running via standard python if needed, 
    # though usually invoked via `pytest`
    unittest.main()