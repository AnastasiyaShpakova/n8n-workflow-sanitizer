import json
import re
import copy

def test_webhook_id_compatibility():
    """
    Tests whether changing webhookId to a constant string
    breaks the JSON structure or basic n8n compatibility.
    """
    print("Running test_webhook_id_compatibility...")

    # Synthetic workflow with a webhook node
    workflow = {
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "test-webhook"},
                "id": "node-1",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [100, 100],
                "webhookId": "original-uuid-12345"
            }
        ],
        "connections": {}
    }

    # Scenario 1: Replace with constant
    workflow_masked = copy.deepcopy(workflow)
    workflow_masked["nodes"][0]["webhookId"] = "[MASKED_WEBHOOK_ID]"

    try:
        json_str = json.dumps(workflow_masked)
        json.loads(json_str)
        print("  - JSON Integrity: PASS")
    except Exception as e:
        print(f"  - JSON Integrity: FAIL ({e})")
        return False

    # Note: Actual n8n import test requires a running n8n instance.
    # In this environment, we verify that the key 'webhookId' is preserved
    # and the value is a string, which is the basic requirement for n8n JSON.
    if "webhookId" in workflow_masked["nodes"][0] and isinstance(workflow_masked["nodes"][0]["webhookId"], str):
        print("  - Basic n8n schema requirement: PASS")
    else:
        print("  - Basic n8n schema requirement: FAIL")
        return False

    print("Result: webhookId masking strategy is structurally safe.")
    return True

if __name__ == "__main__":
    test_webhook_id_compatibility()
