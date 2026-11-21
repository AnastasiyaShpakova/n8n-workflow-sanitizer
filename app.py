import json
import re
import os
import urllib.parse
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10MB limit

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Configuration & Patterns ---

PATTERNS_MASK = {
    'api_key': r'(?i)(?:api[_-]?key|auth[_-]?token|secret|password)["\s:]+([a-zA-Z0-9_\-]{16,})',
    'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    'generic_token': r'\b([a-zA-Z0-9]{32,})\b',
    'js_literal': r"(?i)(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    'bearer_token': r'(?i)Bearer\s+([a-zA-Z0-9\._\-\~\+]{8,})',
    'telegram_token': r'\b(\d{8,12}:[a-zA-Z0-9_\-]{30,})\b'
}

PATTERNS_SUSPICIOUS = {
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'webhook_url': r'https?://[^\s<>"]+/webhook/[a-zA-Z0-9_-]+',
    'phone': r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}',
    'internal_domain': r'[\w-]+\.(?:local|internal|lan)$'
}

SENSITIVE_FIELD_NAMES = {
    'apikey', 'accesstoken', 'clientsecret', 'password',
    'secrettoken', 'authtoken', 'authorization', 'x-api-key'
}

def mask_value(value, label):
    return f"[MASKED_{label.upper()}]"

def is_n8n_expression(data):
    if not isinstance(data, str):
        return False
    # Используем strip() только для проверки, чтобы не менять оригинальные строки
    s_data = data.strip()
    return (s_data.startswith('{{') and s_data.endswith('}}')) or \
           (s_data.startswith('=') and s_data[1:].strip().startswith('{{') and s_data.endswith('}}'))

def find_security_risks(data, risks, path='root'):
    if isinstance(data, dict):
        for k, v in data.items():
            current_path = f"{path}.{k}" if path != 'root' else k
            if k == 'allowUnauthorizedCerts' and v is True:
                risks.append(f"Обнаружена опция `allowUnauthorizedCerts: true` по пути {current_path}. Это может быть небезопасно в продакшене.")
            find_security_risks(v, risks, current_path)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            find_security_risks(item, risks, f"{path}[{i}]")

def sanitize_recursive(data, stats, report_entries, path='root', in_credentials=False):
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            # 1. Context-aware ID masking (Credentials)
            if k in ['id', 'name'] and in_credentials:
                stats['masked'] += 1
                stats['detected'] += 1
                report_entries.append({
                    'type': 'credential_id',
                    'status': 'Автоматически очищено',
                    'context': f"{path}.{k}",
                    'value': '***'
                })
                new_dict[k] = mask_value(v, 'cred_id')
                continue

            # 2. STRICT PROTECT: Technical node properties
            if k in ['id', 'name', 'type', 'position']:
                new_dict[k] = v
                continue

            # 3. Infrastructure IDs
            if k in ['instanceId', 'credentialsId']:
                stats['masked'] += 1
                stats['detected'] += 1
                report_entries.append({
                    'type': 'infrastructure_id',
                    'status': 'Автоматически очищено',
                    'context': f"{path}.{k}",
                    'value': '***'
                })
                new_dict[k] = mask_value(v, 'infra')
                continue

            current_path = f"{path}.{k}" if path != 'root' else k
            next_in_credentials = in_credentials or (k == 'credentials')

            if k.lower() in SENSITIVE_FIELD_NAMES and isinstance(v, str):
                if not is_n8n_expression(v):
                    stats['masked'] += 1
                    stats['detected'] += 1
                    report_entries.append({
                        'type': 'sensitive_field',
                        'status': 'Автоматически очищено',
                        'context': current_path,
                        'value': '***'
                    })
                    new_dict[k] = mask_value(v, 'field')
                    continue

            new_dict[k] = sanitize_recursive(v, stats, report_entries, current_path, in_credentials=next_in_credentials)
        return new_dict

    elif isinstance(data, list):
        return [sanitize_recursive(item, stats, report_entries, f"{path}[{i}]", in_credentials=in_credentials) for i, item in enumerate(data)]

    elif isinstance(data, str):
        if is_n8n_expression(data):
            return data

        if data.startswith('{') and data.endswith('}'):
            try:
                inner_json = json.loads(data)
                inner_stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
                inner_report = []
                sanitized_inner = sanitize_recursive(inner_json, inner_stats, inner_report, path=f"{path}(inner)", in_credentials=in_credentials)
                stats['detected'] += inner_stats['detected']
                stats['masked'] += inner_stats['masked']
                stats['suspicious'] += inner_stats['suspicious']
                report_entries.extend(inner_report)
                return json.dumps(sanitized_inner, ensure_ascii=False)
            except json.JSONDecodeError:
                pass

        # 1. Mask credentials in URLs first to avoid false positives in general patterns
        if data.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(data)
            if parsed.username or parsed.password:
                # Construct new netloc: [MASKED_URL_PASS]@host:port
                netloc_parts = parsed.netloc.split('@')
                host_port = netloc_parts[-1]
                masked_netloc = f"[MASKED_URL_PASS]@{host_port}"

                sanitized_url = urllib.parse.urlunparse((
                    parsed.scheme,
                    masked_netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))

                stats['masked'] += 1
                stats['detected'] += 1
                report_entries.append({
                    'type': 'url_password',
                    'status': 'Автоматически очищено',
                    'context': path,
                    'value': '***'
                })
                return sanitized_url

        for label, pattern in PATTERNS_MASK.items():
            match = re.search(pattern, data)
            if match:
                stats['masked'] += 1
                stats['detected'] += 1
                if label == 'js_literal':
                    replacement = f"[MASKED_{label.upper()}]"
                    start, end = match.span(1)
                    masked_data = data[:start] + replacement + data[end:]
                elif label in ['bearer_token', 'telegram_token', 'api_key']:
                    start, end = match.span(1)
                    masked_data = data[:start] + f"[MASKED_{label.upper()}]" + data[end:]
                else:
                    masked_data = mask_value(data, label)
                report_entries.append({
                    'type': label,
                    'status': 'Автоматически очищено',
                    'context': path,
                    'value': '***'
                })
                return masked_data

        if "webhookId" in path:
            stats['suspicious'] += 1
            stats['detected'] += 1
            report_entries.append({
                'type': 'webhook_id',
                'status': 'Риск публикации (Не решено)',
                'context': path,
                'value': '***'
            })
            return data

        for label, pattern in PATTERNS_SUSPICIOUS.items():
            if re.search(pattern, data):
                stats['suspicious'] += 1
                stats['detected'] += 1
                report_entries.append({
                    'type': label,
                    'status': 'Требует проверки',
                    'context': path,
                    'value': '***'
                })

        return data
    else:
        return data

def verify_sanitization(original, sanitized, stats, report_entries):
    verification_errors = []

    # 1. Strict Node Properties check
    orig_nodes = {n['id']: n for n in original.get('nodes', [])}
    sani_nodes = {n['id']: n for n in sanitized.get('nodes', [])}

    if len(orig_nodes) != len(sani_nodes):
        verification_errors.append("Количество нод изменилось!")
        return verification_errors

    for nid, node in orig_nodes.items():
        if nid not in sani_nodes:
            verification_errors.append(f"Нода {nid} пропала!")
            continue
        s_node = sani_nodes[nid]
        for prop in ['name', 'type', 'position']:
            if node.get(prop) != s_node.get(prop):
                verification_errors.append(f"Свойство {prop} ноды {nid} было изменено!")

    # 2. Connection Graph Integrity
    orig_conn = json.dumps(original.get('connections', {}), sort_keys=True)
    sani_conn = json.dumps(sanitized.get('connections', {}), sort_keys=True)
    if orig_conn != sani_conn:
        verification_errors.append("Граф соединений (connections) был изменен!")

    # 3. Expression Integrity Check
    def get_expressions_map(data, path='root', expr_map=None):
        if expr_map is None: expr_map = {}
        if isinstance(data, str) and is_n8n_expression(data):
            expr_map[path] = data
        elif isinstance(data, dict):
            for k, v in data.items():
                get_expressions_map(v, f"{path}.{k}", expr_map)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                get_expressions_map(item, f"{path}[{i}]", expr_map)
        return expr_map

    orig_expr_map = get_expressions_map(original)
    sani_expr_map = get_expressions_map(sanitized)

    for path, orig_val in orig_expr_map.items():
        if path not in sani_expr_map:
            verification_errors.append(f"Выражение по пути {path} пропало!")
            continue
        sani_val = sani_expr_map[path]
        if orig_val != sani_val:
            was_masked = any(entry['context'] == path and entry['status'] == 'Автоматически очищено'
                             for entry in report_entries)
            if not was_masked:
                verification_errors.append(f"Выражение по пути {path} было изменено без санкции маскировки!")

    # 4. Leak check for passwords in URLs
    sani_str = json.dumps(sanitized, ensure_ascii=False)
    if re.search(r'https?://[^:]+:[^@]+@', sani_str):
        verification_errors.append("Обнаружены возможные пароли в URL (формат user:pass@host)")

    return verification_errors

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не загружен'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    try:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        content = file.read().decode('utf-8')
        workflow = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({'error': 'Невалидный JSON файл'}), 400

    stats = {'detected': 0, 'masked': 0, 'suspicious': 0}
    report_entries = []
    sanitized_workflow = sanitize_recursive(workflow, stats, report_entries)
    v_errors = verify_sanitization(workflow, sanitized_workflow, stats, report_entries)
    if v_errors:
        return jsonify({'error': f"Ошибка верификации: {', '.join(v_errors)}"}), 500

    public_filename = f"public_{timestamp}.json"
    report_filename = f"report_{timestamp}.md"
    public_json_path = os.path.join(UPLOAD_FOLDER, public_filename)
    report_md_path = os.path.join(UPLOAD_FOLDER, report_filename)

    with open(public_json_path, 'w', encoding='utf-8') as f:
        json.dump(sanitized_workflow, f, ensure_ascii=False, indent=2)

    with open(report_md_path, 'w', encoding='utf-8') as f:
        f.write(f"# Отчет о приватности - n8n Workflow Sanitizer\n")
        f.write(f"Дата обработки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        security_warnings = []
        find_security_risks(sanitized_workflow, security_warnings)

        f.write(f"## Статистика\n")
        f.write(f"- Обнаружено элементов: {stats['detected']}\n")
        f.write(f"- Автоматически замаскировано: {stats['masked']}\n")
        f.write(f"- Нерешённые риски: {sum(1 for e in report_entries if e['status'] == 'Риск публикации (Не решено)')}\n")
        f.write(f"- Предупреждения о небезопасных настройках: {len(security_warnings)}\n")
        f.write(f"- Прочие элементы для проверки: {sum(1 for e in report_entries if e['status'] == 'Требует проверки')}\n\n")

        f.write(f"## Предупреждения по безопасности\n")
        if not security_warnings:
            f.write("Критических предупреждений по конфигурации не найдено.\n")
        else:
            f.write("\n".join([f"- {w}" for w in security_warnings]) + "\n")

        # Publication Status
        unresolved_risks = [e['type'] for e in report_entries if e['status'] == 'Риск публикации (Не решено)']
        if unresolved_risks:
            f.write(f"\n## ⚠️ ВНИМАНИЕ: Файл НЕ ГОТОВ к публичной публикации\n")
            f.write(f"Обнаружены нерешенные риски безопасности: {', '.join(set(unresolved_risks))}.\n")
            f.write(f"Рекомендуется вручную заменить эти значения на безопасные заглушки перед загрузкой на GitHub.\n")
        else:
            f.write(f"\n## Статус публикации: Готов к проверке\n")
            f.write(f"Критических нерешенных рисков не обнаружено.\n")

        f.write(f"\n## Детали\n")
        f.write(f"| Тип | Статус | JSON-путь | Рекомендация |\n")
        f.write(f"| --- | --- | --- | --- |\n")
        for entry in report_entries:
            if entry['status'] == 'Требует проверки':
                rec = "Проверьте значение вручную"
            elif entry['status'] == 'Риск публикации (Не решено)':
                rec = "Значение требует проверки перед публикацией"
            else:
                rec = "Замаскировано"
            f.write(f"| {entry['type']} | {entry['status']} | {entry['context']} | {rec} |\n")
        f.write(f"\n\n**Предупреждение**: Этот отчет не гарантирует 100% очистки. Всегда проверяйте итоговый файл перед публикацией.\n")

    return jsonify({
        'stats': stats,
        'public_file': public_filename,
        'report_file': report_filename
    })

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
