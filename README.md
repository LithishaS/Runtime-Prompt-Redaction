# 🛡️ Runtime Prompt Protection

A Python-based MITM Proxy tool that provides runtime protection for **VS Code GitHub Copilot Chat** by detecting and redacting sensitive information from prompts and uploaded files before they are sent to the AI model.

---

## 📌 Project Overview

This project enhances the security of AI-assisted coding by intercepting requests made from **VS Code GitHub Copilot Chat**.

The tool analyzes prompts and uploaded files for sensitive information such as API keys, passwords, access tokens, email addresses, and confidential identifiers. Detected sensitive content is redacted or blocked before the request is forwarded, helping prevent accidental exposure of confidential data.

---

## ✨ Features

- Detect sensitive information in prompts
- Redact API keys, passwords, and access tokens
- Detect email addresses and personal identifiers
- Scan uploaded files for sensitive content
- Block confidential file uploads
- Forward sanitized prompts to GitHub Copilot Chat
- Capture AI responses
- Generate structured runtime logs

---

## 🛠 Technologies Used

- Python
- MITM Proxy
- GitHub Copilot Chat
- JSON
- Regular Expressions (Regex)

---

## ⚙️ Runtime Protection Workflow

```text
VS Code GitHub Copilot Chat
               │
               ▼
         MITM Proxy
               │
               ▼
Extract User Prompt
               │
               ▼
Sensitive Data Detection
               │
               ▼
Prompt Redaction
               │
               ▼
Uploaded File Analysis
               │
               ▼
Block Confidential Files
               │
               ▼
Forward Sanitized Request
               │
               ▼
Receive AI Response
               │
               ▼
Generate Runtime Log
```

---

## 📂 Project Structure

```text
vscode-copilot-runtime-protection/

│── security_chat.py
│── README.md
│──.gitignore
```

---

## 🔒 Sensitive Data Detection

The tool detects and protects information such as:

- API Keys
- Passwords
- Access Tokens
- Secrets
- Email Addresses
- Phone Numbers
- PAN Numbers
- Aadhaar Numbers
- Salary Information
- Bank Account Details

---

## 🚀 How It Works

1. Intercept requests sent from VS Code GitHub Copilot Chat.
2. Extract the latest user prompt.
3. Scan prompts using predefined security rules.
4. Analyze uploaded files for sensitive information.
5. Redact sensitive content or block confidential files.
6. Forward the sanitized request to GitHub Copilot.
7. Capture the AI response.
8. Log the protected interaction.

---

## 📊 Sample Output

```text
Original Prompt:
My API key is sk-xxxxxxxxxxxxxxxx

Sanitized Prompt:
My API key is [REDACTED_API_KEY]

Risk Detected:
✔ API_KEY

Action Taken:
Prompt Redacted

Files:
ALLOWED

Status:
COMPLETED
```

---
