# CyberWatch Research Project

Python/Flask security monitoring project.

## New Laptop Setup

1. Copy the full project folder to the new laptop.
2. Install Python 3.10, 3.11, or 3.12.
3. During Python install, tick **Add python.exe to PATH**.
4. Double-click:

```bat
setup_full_project.bat
```

The setup file rebuilds `.venv` for that laptop and installs all Python packages.
Do not copy an old `.venv` from another laptop; virtual environments are not portable.

## Run Full Project

Normal run:

```bat
start_full_project.bat
```

Administrator run for real network packet capture:

```bat
start_full_project_admin.bat
```

Main URLs:

- Main dashboard: `http://localhost:5000`
- Network Flow Monitor: `http://localhost:5001`
- Web Access Monitor: `http://localhost:5002`
- File & Mouse Monitor: `http://localhost:5003`
- API Behavior Analysis: `http://localhost:5005/api-analyzer`

## Run Only API Behavior Analysis

```bat
start_api_5005.bat
```

Open:

```text
http://localhost:5005/api-analyzer
```

## Manual System Tools

For live packet capture, install Npcap:

```text
https://npcap.com/
```

Then run `start_full_project_admin.bat`.

If `netifaces` fails during setup, install Microsoft C++ Build Tools and run setup again:

```text
https://visualstudio.microsoft.com/visual-cpp-build-tools/
```
