# 🛡️ Who is there

This Python script is designed to detect suspicious processes related to active **Meterpreter shells** on your system and optionally **terminate them** automatically.

> ⚠️ **Warning:** This script is intended for educational and defensive purposes in controlled environments. Misuse may lead to legal consequences and/or system damage.

---

## 🚀 Features

- Detects suspicious Meterpreter-like processes.
- Displays information such as PID, process name, and active ports.
- Offers to automatically kill detected malicious processes.
- Works on Unix/Linux systems (can be adapted for Windows).

---

## 🧰 Requirements

- Python 3.7 or higher
- Administrator/root privileges

  

## 🥃 Quick start

```bash
git clone https://github.com/kur0bai/whoisthere.git
cd whoisthere
pip install -r requirements.txt
ifconfig
python main.py --interface=youreth0
