# SYSDIFF
# sysdiff (Modern Clone of Windows NT Sysdiff)

A modern, open-source implementation of Microsoft's legacy `sysdiff.exe` utility from Windows NT/2000 Resource Kits.

This tool helps capture **system state snapshots** (filesystem and registry), compare them, and optionally generate deployment-compatible output (planned).

## ✨ Features

- Capture a **snapshot** of file and registry state (`/snap`)
- Compare system state changes after an install (`/diff`)
- Planned: Generate `.INF` style deployment packages (`/inf`)
- Uses MD5 checksums for file integrity verification
- Supports recursive file and registry key traversal
- Compatible with modern Windows (10/11)

## 🛠️ Usage

```bash
sysdiff /snap <snapshot_file>

