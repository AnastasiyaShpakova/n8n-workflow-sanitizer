import json
import io
import os
import re
from app import app, sanitize_recursive, is_n8n_expression, verify_sanitization

def test_expressions_integrity():
    print("Running test_expressions_integrity...")
    # Тестируем оба варианта: с пробелом и без
    test_cases = [
        {"field": "my_field", "val": "={{ $json.id }}", "corrupt": "={{ $json.wrong }}"},
        {"field": "my_field_space", "val": "= {{ $json.id }}", "corrupt": "= {{ $json.wrong }}"}
    ]

    for case in test_cases:
        workflow = {
            "nodes": [
                {
                    "id": "n1",
                    "parameters": {
                        case["field"]: case["val"],
                        "my_secret": "secret-token-1234567890"
                    },
                    "name": "Node1",
                    "type": "n8n-node",
                    "position": [0, 0]
                }
            ],
            "connections": {}
        }

        stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
        report = []
        sanitized = sanitize_recursive(workflow, stats, report)

        # 1. Check that the expression is preserved
        assert sanitized["nodes"][0]["parameters"][case["field"]] == case["val"]

        # 2. Verify that verify_sanitization passes
        errors = verify_sanitization(workflow, sanitized, stats, report)
        assert len(errors) == 0, f"Verification failed for {case['val']}: {errors}"

        # 3. Test corruption detection
        # Manually corrupt an expression
        sanitized["nodes"][0]["parameters"][case["field"]] = case["corrupt"]
        errors = verify_sanitization(workflow, sanitized, stats, report)
        assert len(errors) > 0, f"Corrupted expression {case['val']} was not detected!"
        assert any("изменено без санкции маскировки" in e for e in errors)

    print("  - Expressions integrity: PASS")

def test_webhook_id_risk():
    print("Running test_webhook_id_risk...")
    workflow = {
        "nodes": [
            {
                "id": "n1",
                "parameters": {
                    "path": "test"
                },
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "position": [0, 0],
                "webhookId": "original-secret-id"
            }
        ],
        "connections": {}
    }

    stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
    report = []
    sanitized = sanitize_recursive(workflow, stats, report)

    # 1. Check that webhookId is NOT changed
    assert sanitized["nodes"][0]["webhookId"] == "original-secret-id"

    # 2. Check that it's marked as unresolved risk
    assert any(e['type'] == 'webhook_id' and e['status'] == 'Риск публикации (Не решено)' for e in report)
    print("  - WebhookId risk marking: PASS")

def test_credentials_masking():
    print("Running test_credentials_masking...")
    workflow = {
        "nodes": [
            {
                "id": "n1",
                "name": "Node1",
                "parameters": {},
                "type": "t",
                "position": [0,0]
            }
        ],
        "connections": {},
        "credentials": {
            "telegramApi": {
                "id": "cred-123",
                "name": "MyBot"
            }
        }
    }

    stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
    report = []
    # Manually simulate the recursive call starting at root
    # To ensure 'credentials' key triggers in_credentials=True
    sanitized = sanitize_recursive(workflow, stats, report)

    # 1. Node ID should remain
    assert sanitized["nodes"][0]["id"] == "n1"
    # 2. Credential ID/Name should be masked
    assert sanitized["credentials"]["telegramApi"]["id"] == "[MASKED_CRED_ID]"
    assert sanitized["credentials"]["telegramApi"]["name"] == "[MASKED_CRED_ID]"
    print("  - Credentials masking: PASS")

def test_integration_security_warnings():
    print("Running test_integration_security_warnings...")
    client = app.test_client()

    workflow = {
        "nodes": [
            {
                "id": "n1",
                "parameters": {
                    "options": {
                        "allowUnauthorizedCerts": True
                    },
                    "webhookId": "secret-webhook-id"
                },
                "name": "Node1",
                "type": "t",
                "position": [0,0]
            }
        ],
        "connections": {}
    }

    data_bytes = json.dumps(workflow).encode('utf-8')
    response = client.post(
        '/process',
        data={'file': (io.BytesIO(data_bytes), 'test.json', 'application/json')},
        content_type='multipart/form-data'
    )

    assert response.status_code == 200
    res_json = response.get_json()

    # Get the report file
    report_filename = res_json['report_file']
    report_path = os.path.join('uploads', report_filename)

    with open(report_path, 'r', encoding='utf-8') as f:
        report_content = f.read()

    # Check for security warning
    assert "allowUnauthorizedCerts" in report_content
    # Check for unresolved risk warning
    assert "⚠️ ВНИМАНИЕ: Файл НЕ ГОТОВ к публичной публикации" in report_content
    assert "webhook_id" in report_content

    print("  - Integration security warnings: PASS")

def test_synthetic_cases():
    print("Running test_synthetic_cases...")
    client = app.test_client()

    # Синтетический workflow для проверки всех новых требований
    workflow = {
        "nodes": [
            {
                "id": "n1",
                "parameters": {
                    "options": {"allowUnauthorizedCerts": True}
                },
                "webhookId": "secret-webhook-123",
                "name": "Webhook Node",
                "type": "n8n-nodes-base.webhook",
                "position": [0, 0]
            },
            {
                "id": "n2",
                "parameters": {
                    "options": {"allowUnauthorizedCerts": True},
                    "apiKey": "real-api-key-secret-12345"
                },
                "name": "HTTP Node",
                "type": "n8n-nodes-base.httpRequest",
                "position": [100, 0]
            }
        ],
        "connections": {}
    }

    data_bytes = json.dumps(workflow).encode('utf-8')
    response = client.post(
        '/process',
        data={'file': (io.BytesIO(data_bytes), 'test.json', 'application/json')},
        content_type='multipart/form-data'
    )
    assert response.status_code == 200
    res_json = response.get_json()

    # Проверка выходного JSON: webhookId должен остаться неизменным
    public_file_path = os.path.join('uploads', res_json['public_file'])
    with open(public_file_path, 'r', encoding='utf-8') as f:
        public_json = json.load(f)
    assert public_json["nodes"][0]["webhookId"] == "secret-webhook-123", "webhookId был изменен в JSON!"

    # Проверка отчета
    report_path = os.path.join('uploads', res_json['report_file'])
    with open(report_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Рекомендация для webhookId (не "Замаскировано")
    assert "Значение требует проверки перед публикацией" in content
    assert "webhook_id" in content

    # 2. JSON-пути для allowUnauthorizedCerts (оба вхождения)
    assert "allowUnauthorizedCerts: true` по пути nodes[0].parameters.options.allowUnauthorizedCerts" in content
    assert "allowUnauthorizedCerts: true` по пути nodes[1].parameters.options.allowUnauthorizedCerts" in content

    # 3. Статистика (различение типов)
    assert "Автоматически замаскировано: 1" in content # apiKey
    assert "Нерешённые риски: 1" in content # webhookId
    assert "Предупреждения о небезопасных настройках: 2" in content # 2x allowUnauthorizedCerts

    # 4. Отсутствие секретов в отчете
    assert "secret-webhook-123" not in content
    assert "real-api-key-secret-12345" not in content

    print("  - Synthetic cases: PASS")

def test_advanced_secrets_masking():
    print("Running test_advanced_secrets_masking...")
    test_cases = [
        {"name": "Bearer token", "val": "Authorization: Bearer abc123def456", "expected": "Authorization: Bearer [MASKED_BEARER_TOKEN]"},
        {"name": "Telegram token", "val": "12345678:AAAbbcC-DDeefGHiIjKlMnOpQrStUvWxYz12345", "expected": "[MASKED_TELEGRAM_TOKEN]"},
        {"name": "URL with password", "val": "https://admin:secret123@api.service.com/v1?q=1#frag", "expected": "https://[MASKED_URL_PASS]@api.service.com/v1?q=1#frag"},
        {"name": "URL with port", "val": "https://user:pass@localhost:8080/api", "expected": "https://[MASKED_URL_PASS]@localhost:8080/api"},
        {"name": "URL percent encoded", "val": "https://user%40mail.com:p%40ss@host.com", "expected": "https://[MASKED_URL_PASS]@host.com"},
        {"name": "Safe URL", "val": "https://api.service.com/v1", "expected": "https://api.service.com/v1"},
        {"name": "Safe Bearer", "val": "Bearer short", "expected": "Bearer short"},
    ]

    for case in test_cases:
        workflow = {
            "nodes": [{"id": "n1", "parameters": {"field": case["val"]}, "name": "N", "type": "T", "position": [0,0]}],
            "connections": {}
        }
        stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
        report = []
        sanitized = sanitize_recursive(workflow, stats, report)
        actual = sanitized["nodes"][0]["parameters"]["field"]
        assert actual == case["expected"], f"Failed {case['name']}: expected {case['expected']}, got {actual}"

    print("  - Advanced secrets masking: PASS")

if __name__ == "__main__":
    try:
        test_expressions_integrity()
        test_webhook_id_risk()
        test_credentials_masking()
        test_advanced_secrets_masking()
        test_integration_security_warnings()
        test_synthetic_cases()
        print("\nAll detailed tests completed successfully.")
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
