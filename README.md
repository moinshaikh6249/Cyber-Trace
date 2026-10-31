 <p align="center">
  <img src="assets/cybertrace.ico.png" alt="CyberTrace Logo" width="130">
</p>

<h1 align="center">CyberTrace</h1>

<h3 align="center">Digital Forensics & Evidence Intelligence Platform</h3>

<p align="center">
  <strong>Investigate. Preserve. Verify. Report.</strong>
</p>

<p align="center">
  A desktop-based digital forensics application for organizing investigations, preserving digital evidence, validating integrity, and generating structured forensic reports.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/GUI-PySide6-41CD52?logo=qt&logoColor=white" alt="PySide6">
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Hashing-SHA--256-orange" alt="SHA-256">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white" alt="Windows">
</p>

---

## Overview

**CyberTrace** is a local desktop application designed to support digital-forensics investigations through centralized case management, evidence organization, integrity verification, chain-of-custody tracking, file examination, and investigation reporting.

Built using Python, PySide6, and SQLite, CyberTrace combines essential forensic investigation workflows into a unified desktop environment.

The application focuses on evidence traceability, data integrity, structured investigation management, and accessible forensic documentation.

## Application Preview

<p align="center">
  <img src="assets/cybertrace-preview.png" alt="CyberTrace Investigation Dashboard" width="100%">
</p>

*Dashboard preview showing the application populated with synthetic demonstration data.*

## Key Features

### 1. Investigation Management
- Create and manage investigation cases.
- Track investigation lifecycle and case health.
- Organize investigation information.
- Monitor case progress and activities.

### 2. Digital Evidence Management
- Acquire and register digital evidence.
- Organize evidence within investigation cases.
- Maintain preserved evidence copies.
- Manage evidence records and associated information.

### 3. Evidence Integrity Verification
- Calculate SHA-256 cryptographic hashes.
- Verify preserved evidence copies against recorded hashes.
- Detect integrity mismatches.
- Maintain evidence integrity information.

### 4. Chain of Custody
- Record evidence handling events.
- Maintain custody documentation.
- Review custody history.
- Verify recorded custody chains.

### 5. Digital Evidence Examination
- Examine file metadata.
- Record analysis results.
- Add investigation notes and findings.
- Organize examination information.

### 6. Timeline Intelligence
- Review investigation timelines.
- Replay recorded investigation events.
- Explore event sequences.
- Examine relationships across evidence records.

### 7. Forensic Reporting
- Generate HTML forensic reports.
- Prepare executive summaries.
- Organize investigation findings.
- Present evidence-related information in structured reports.

### 8. User Experience
- Modern desktop interface.
- Dark and light themes.
- Centralized investigation dashboard.
- Organized investigation workspace.

## Forensic Investigation Workflow

CyberTrace follows a structured investigation workflow:

<p align="center">
  <strong>Investigation Creation</strong>
  <br>↓<br>
  <strong>Evidence Registration</strong>
  <br>↓<br>
  <strong>Cryptographic Hash Calculation</strong>
  <br>↓<br>
  <strong>Evidence Preservation</strong>
  <br>↓<br>
  <strong>Chain of Custody Recording</strong>
  <br>↓<br>
  <strong>Evidence Examination</strong>
  <br>↓<br>
  <strong>Timeline & Relationship Analysis</strong>
  <br>↓<br>
  <strong>Forensic Report Generation</strong>
</p>

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| PySide6 | Desktop graphical user interface |
| SQLite | Local database management |
| SHA-256 | Cryptographic evidence hashing |
| HTML | Forensic report generation |
| unittest | Automated testing |
| PyInstaller | Windows application packaging |
| Inno Setup 6 | Windows installer creation |

## Project Architecture

CyberTrace uses a modular desktop application architecture.

### Presentation Layer
Responsible for:
- Desktop interface
- Investigation dashboard
- User interactions
- Case and evidence views

### Application Layer
Responsible for:
- Investigation workflows
- Case management operations
- Application-level business logic

### Forensic Services Layer
Responsible for:
- Evidence hashing
- Integrity verification
- File metadata examination
- Timeline analysis
- Report generation

### Persistence Layer
Responsible for:
- SQLite database operations
- Investigation records
- Evidence information
- Local data storage

## Repository Structure

```text
Cyber-Trace/
│
├── assets/
│   ├── cybertrace-preview.png
│   ├── cybertrace.ico
│   └── cybertrace.ico.png
│
├── data/
├── database/
├── demo_fixtures/
├── evidence/
├── installer/
├── tests/
│
├── CyberTrace.spec
├── README.md
└── main.py
```

*The repository may contain additional modules, services, and supporting files.*

## Installation & Setup

### Requirements

- Python 3.10 or later
- Windows operating system for the documented PowerShell commands
- PySide6

### Step 1: Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
```

Navigate into the project directory:

```bash
cd Cyber-Trace
```

### Step 2: Create a Virtual Environment

```powershell
py -m venv .venv
```

Activate the environment:

```powershell
.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install PySide6
```

### Step 4: Launch CyberTrace

```powershell
python main.py
```

## Running Tests

CyberTrace includes an automated test suite using Python's built-in `unittest` framework.

Execute:

```powershell
python -m unittest discover -s tests -v
```

This command discovers and executes the tests available under the `tests` directory.

## Windows Application Packaging

CyberTrace includes a PyInstaller specification file and an Inno Setup installer script.

### Step 1: Install PyInstaller

```powershell
python -m pip install PyInstaller
```

### Step 2: Build the Application

```powershell
pyinstaller --noconfirm CyberTrace.spec
```

### Step 3: Generate the Installer

Open the installer script:

```text
installer/CyberTrace.iss
```

Compile it using Inno Setup 6.

**Packaging Note:** The current packaging configuration contains absolute `D:\CyberTrace` paths. Update the paths in `CyberTrace.spec` and `installer/CyberTrace.iss` if the repository is located elsewhere.

## Local Data Management

CyberTrace stores investigation-related information locally.

| Data Category | Source Execution | Packaged Windows Build |
|---|---|---|
| Case Database | `data/` | `%LOCALAPPDATA%\CyberTrace` |
| Preserved Evidence | `evidence/` | `%LOCALAPPDATA%\CyberTrace` |
| Generated Reports | `reports/` | `%LOCALAPPDATA%\CyberTrace` |

**Important:** Back up investigation databases, preserved evidence, and generated reports regularly. Protect sensitive investigation information from unauthorized access.

## Security & Evidence Handling

CyberTrace is designed with evidence integrity and traceability in mind.

Recommended evidence-handling practices:

- Work only with legally authorized digital evidence.
- Preserve original evidence and examine verified working copies.
- Record cryptographic hashes for integrity reference.
- Validate evidence integrity during relevant operations.
- Maintain appropriate chain-of-custody documentation.
- Protect local databases and exported investigation reports.
- Avoid committing sensitive evidence, credentials, or investigation records to public repositories.

**Disclaimer:** CyberTrace is an investigation management and evidence review application. Its outputs should not automatically be considered legally certified forensic conclusions. Evidence admissibility and forensic validity depend on appropriate procedures, independent validation, and applicable legal requirements.

## Future Enhancements

Potential areas for future development include:

- Advanced file signature identification.
- Additional cryptographic hash algorithms.
- Enhanced evidence integrity audit history.
- Advanced forensic timeline correlation.
- Interactive evidence relationship visualization.
- PDF forensic report generation.
- Advanced investigation search and filtering.
- Role-based investigator access controls.
- Enhanced automated forensic validation.
- Improved application packaging and deployment.

*These are potential enhancements and do not necessarily represent currently implemented functionality.*

## Project Information

| Attribute | Details |
|---|---|
| Project Name | CyberTrace |
| Category | Digital Forensics & Cybersecurity |
| Application Type | Desktop Application |
| Programming Language | Python |
| GUI Framework | PySide6 |
| Database | SQLite |
| Integrity Algorithm | SHA-256
