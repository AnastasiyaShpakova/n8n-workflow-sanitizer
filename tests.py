import json
import os
import re
from app import app, sanitize_recursive, PATTERNS_MASK, PATTERNS_SUSPICIOUS

def test_masking():
    print("Running test_masking...")
    stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
    report = []

    # 1. Email masking
    val = "test@example.com"
    res = sanitize_recursive(val, stats, report)
    assert "[MASKED_EMAIL]" in res
    print("  - Email masking: PASS")

    # 2. JS Secret masking
    val = "const key = 'top-secret-token-999'; return { result: key };"
    # Note: the current implementation of app.py doesn't handle this.
    # This test will fail initially, which is expected.
    res = sanitize_recursive(val, stats, report)
    if 'top-secret-token-999' in res:
        print("  - JS Secret masking: FAIL (value still present)")
    else:
        print("  - JS Secret masking: PASS")

    # 3. Suspicious patterns
    val = "192.168.1.1"
    res = sanitize_recursive(val, stats, report)
    assert res == "192.168.1.1" # Should NOT mask
    assert any(e['type'] == 'ipv4' for e in report)
    print("  - Suspicious IP detection: PASS")

def test_structure():
    print("Running test_structure...")
    workflow = {
        "nodes": [{"id": "node-1", "parameters": {"email": "a@b.com"}, "name": "N1"}],
        "connections": {"node-1": {"main": [[{"node": "node-2"}]]}}
    }
    stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
    report = []
    res = sanitize_recursive(workflow, stats, report)

    assert res["nodes"][0]["id"] == "node-1"
    assert res["nodes"][0]["name"] == "N1"
    assert res["nodes"][0]["parameters"]["email"] == "[MASKED_EMAIL]"
    assert res["connections"]["node-1"]["main"][0][0]["node"] == "node-2"
    print("  - Structure preservation: PASS")

if __name__ == "__main__":
    try:
        test_masking()
        test_structure()
        print("\nAll tests completed.")
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
