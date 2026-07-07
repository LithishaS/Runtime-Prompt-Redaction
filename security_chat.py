from mitmproxy import http, ctx
from datetime import datetime
import json
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_DIR = os.path.join(BASE_DIR, "vscode_output")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "prompts.json")
RAW_FILE = os.path.join(OUTPUT_DIR, "raw_prompts.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

SENSITIVE_RULES = [
    ("API_KEY", r"sk-[A-Za-z0-9_\-]{10,}"),
    ("PASSWORD", r"(?i)\b(password|passwd|pwd)\b\s*(is|:|=)?\s*[A-Za-z0-9@#$%^&*!._-]{4,}"),
    ("TOKEN", r"(?i)\b(token|access_token|secret)\b\s*(is|:|=)?\s*[A-Za-z0-9@#$%^&*!._-]{6,}"),
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("PHONE", r"\b[6-9]\d{9}\b"),
    ("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    ("AADHAAR", r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    ("SALARY_DATA", r"(?i)\b(salary|payroll|ctc|income)\b"),
    ("BANK_DATA", r"(?i)\b(bank account|account number|ifsc|statement)\b"),
]

FILE_BLOCK_TEXT = "[CONFIDENTIAL_FILE_REMOVED]"


def load(loader):
    ctx.log.info("Runtime prompt protection loaded")
    ctx.log.info(f"Output folder: {OUTPUT_DIR}")


def load_json(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def is_target(flow):
    host = flow.request.pretty_host.lower()
    url = flow.request.pretty_url.lower()

    return (
        flow.request.method == "POST"
        and "api.individual.githubcopilot.com" in host
        and "/v1/messages" in url
    )


def get_request_text(flow):
    try:
        return flow.request.get_text(strict=False)
    except:
        try:
            return flow.request.content.decode("utf-8", errors="ignore")
        except:
            return ""


def get_response_text(flow):
    try:
        return flow.response.get_text(strict=False)
    except:
        try:
            return flow.response.content.decode("utf-8", errors="ignore")
        except:
            return ""


def extract_latest_user_prompt(request_text):
    matches = re.findall(
        r"<userRequest>(.*?)</userRequest>",
        request_text,
        re.DOTALL | re.IGNORECASE
    )

    prompts = []

    for match in matches:
        value = match.replace("\\n", "\n").strip()
        if value:
            prompts.append(value)

    return prompts[-1] if prompts else ""


def sanitize_prompt(text):
    sanitized = text
    findings = []

    for rule_name, pattern in SENSITIVE_RULES:
        if re.search(pattern, sanitized):
            findings.append(rule_name)

            if rule_name == "PASSWORD":
                sanitized = re.sub(
                    pattern,
                    "password [REDACTED_PASSWORD]",
                    sanitized
                )

            elif rule_name == "TOKEN":
                sanitized = re.sub(
                    pattern,
                    "token [REDACTED_TOKEN]",
                    sanitized
                )

            else:
                sanitized = re.sub(
                    pattern,
                    f"[REDACTED_{rule_name}]",
                    sanitized
                )

    return sanitized, list(set(findings))


def detect_sensitive_data(text):
    findings = []

    if not text:
        return findings

    for rule_name, pattern in SENSITIVE_RULES:
        if re.search(pattern, text):
            findings.append(rule_name)

    return list(set(findings))


def replace_prompt_in_request(request_text, original_prompt, sanitized_prompt):
    if not original_prompt or original_prompt == sanitized_prompt:
        return request_text

    modified = request_text

    modified = modified.replace(original_prompt, sanitized_prompt, 1)

    escaped_original = original_prompt.replace("\n", "\\n")
    escaped_sanitized = sanitized_prompt.replace("\n", "\\n")

    modified = modified.replace(escaped_original, escaped_sanitized, 1)

    return modified


def extract_attachments(request_text):
    files = []
    seen = set()

    attachment_blocks = re.findall(
        r"<attachments>(.*?)</attachments>",
        request_text,
        re.IGNORECASE | re.DOTALL
    )

    if not attachment_blocks:
        return []

    latest_attachment_text = attachment_blocks[-1]

    opening_tags = re.findall(
        r"<attachment[^>]*>",
        latest_attachment_text,
        re.IGNORECASE
    )

    for tag in opening_tags:
        match = re.search(
            r'filePath=\\"([^"]+)\\"|filePath="([^"]+)"',
            tag,
            re.IGNORECASE
        )

        if not match:
            continue

        path = match.group(1) or match.group(2)
        path = path.replace("\\\\", "\\").strip()

        file_name = os.path.basename(path)
        file_type = os.path.splitext(file_name)[1].lower()

        key = (file_name + "|" + path).lower()

        if key in seen:
            continue

        seen.add(key)

        scan_text = file_name

        if os.path.exists(path):
            try:
                if file_type in [".txt", ".csv", ".json", ".py", ".js", ".html", ".md"]:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        scan_text += "\n" + f.read()
            except:
                pass

        findings = detect_sensitive_data(scan_text)

        files.append({
            "file_name": file_name,
            "file_type": file_type,
            "file_path": path,
            "risk_detected": len(findings) > 0,
            "findings": findings,
            "action_taken": "BLOCKED" if findings else "ALLOWED"
        })

    return files


def block_confidential_files(request_text, files):
    modified = request_text

    for file in files:
        if not file.get("risk_detected"):
            continue

        file_name = file.get("file_name", "")
        file_path = file.get("file_path", "")

        if file_path:
            modified = modified.replace(file_path, FILE_BLOCK_TEXT)
            modified = modified.replace(file_path.replace("\\", "\\\\"), FILE_BLOCK_TEXT)

        if file_name:
            modified = modified.replace(file_name, FILE_BLOCK_TEXT)

    return modified


def create_pending_log(entry):
    logs = load_json(OUTPUT_FILE)
    logs.append(entry)
    save_json(OUTPUT_FILE, logs)
    return len(logs) - 1


def update_log_output(index, output_response, response_raw):
    logs = load_json(OUTPUT_FILE)

    if index is not None and index < len(logs):
        logs[index]["status"] = "COMPLETED"
        logs[index]["output_response"] = output_response
        save_json(OUTPUT_FILE, logs)

    raw_logs = load_json(RAW_FILE)
    raw_logs.append({
        "timestamp": datetime.now().isoformat(),
        "response_raw": response_raw
    })
    save_json(RAW_FILE, raw_logs)


def extract_response_from_stream(response_text):
    parts = []

    for line in response_text.splitlines():
        line = line.strip()

        if not line.startswith("data:"):
            continue

        line = line.replace("data:", "", 1).strip()

        if not line or line == "[DONE]":
            continue

        try:
            data = json.loads(line)
        except:
            continue

        if data.get("type") == "content_block_delta":
            delta = data.get("delta", {})
            if delta.get("type") == "text_delta":
                value = delta.get("text")
                if value:
                    parts.append(str(value))

        try:
            value = data["choices"][0].get("delta", {}).get("content")
            if value:
                parts.append(str(value))
        except:
            pass

    return "".join(parts).strip()


def request(flow: http.HTTPFlow):
    if not is_target(flow):
        return

    original_request_text = get_request_text(flow)

    original_prompt = extract_latest_user_prompt(original_request_text)
    sanitized_prompt, prompt_findings = sanitize_prompt(original_prompt)

    files = extract_attachments(original_request_text)

    file_findings = []
    for file in files:
        file_findings.extend(file.get("findings", []))

    all_findings = list(set(prompt_findings + file_findings))

    modified_request_text = replace_prompt_in_request(
        original_request_text,
        original_prompt,
        sanitized_prompt
    )

    modified_request_text = block_confidential_files(
        modified_request_text,
        files
    )

    flow.request.set_text(modified_request_text)

    pending_entry = {
        "platform": "VS Code GitHub Copilot Chat",
        "timestamp": datetime.now().isoformat(),
        "url": flow.request.pretty_url,

        "original_prompt": original_prompt,
        "sanitized_prompt": sanitized_prompt,

        "risk_detected": len(all_findings) > 0,
        "findings": all_findings,

        "action_taken": {
            "prompt": "REDACTED" if prompt_findings else "ALLOWED",
            "files": "BLOCKED" if file_findings else "ALLOWED"
        },

        "replacement_sent": FILE_BLOCK_TEXT if file_findings else None,
        "files": files,

        "status": "REQUEST_SENT_WAITING_FOR_RESPONSE",
        "output_response": ""
    }

    log_index = create_pending_log(pending_entry)

    flow.metadata["log_index"] = log_index

    ctx.log.info(f"ORIGINAL PROMPT: {original_prompt}")
    ctx.log.info(f"SANITIZED PROMPT: {sanitized_prompt}")
    ctx.log.info(f"FINDINGS: {all_findings}")


def response(flow: http.HTTPFlow):
    if not is_target(flow):
        return

    response_text = get_response_text(flow)
    output_response = extract_response_from_stream(response_text)

    log_index = flow.metadata.get("log_index")

    update_log_output(log_index, output_response, response_text)

    ctx.log.info("OUTPUT UPDATED IN JSON")