# server-log-analyzer
Python tool to parse server logs, detect failed logins, flag suspicious IPs, and generate security reports.

# 🔍 Server Log Analyzer

A Python tool to parse server logs, detect failed login attempts, identify suspicious IP addresses, and generate security reports.

## 📋 Features

- ✅ Parses server log files automatically
- ✅ Detects failed login attempts
- ✅ Flags suspicious IPs (brute force patterns - 3+ failed attempts)
- ✅ Counts 404 errors
- ✅ Tracks successful logins
- ✅ Exports detailed report to CSV
- ✅ Easy to extend for any log format

## 🛠️ Tech Stack

- Python 3.x
- Regex (re module)
- Collections (Counter)
- CSV module
- Datetime module

## 🚀 How to Run

### 1. Clone the repository
```bash
git clone https://github.com/Nehanena/server-log-analyzer.git
cd server-log-analyzer
