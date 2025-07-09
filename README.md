# SYSDIFF
# sysdiff — Modern Clone of Windows NT Sysdiff

A modern C++ reimplementation of Microsoft's legacy `sysdiff.exe` from the Windows NT/2000 Resource Kits. This tool allows system administrators and developers to capture and compare system state snapshots — including filesystem and registry — for deployment or auditing purposes.

---

## 🧩 Features

- 🔍 Capture system state (files + registry) before changes
- 📊 Compare system changes after software installs
- 📝 Planned: Generate `.INF` deployment scripts
- 💾 MD5-based file integrity checking
- 🗂 Recursive directory traversal
- 🧠 Minimal, efficient logic in C++20 using Visual Studio 2020 
- 🖥 Supports Windows 10 and 11

---

## ⚙️ Usage

```bash
sysdiff /snap <snapshot_file>
sysdiff /diff <snapshot_file> <diff_file>
sysdiff /inf <diff_file> <output_directory>
Example Scenario
Suppose you installed an app manually on one computer. Instead of repeating the install manually on others, you could:

Run sysdiff /snap before installation.

Install the app.

Run sysdiff /diff to capture changes.

Create an INF package with sysdiff /inf.

Use the INF in an unattended setup or script on other machines.
