# PIDsec

Made by **SNB220**.

PIDsec is a Windows command-line process triage tool for DFIR, debugging, system inspection, and basic inter-process communication review. It reports process identity, ancestry, command line, memory, CPU time, open files, child processes, active network connections, executable hashes, and explainable suspicion indicators.

See [MENU.md](MENU.md) for the full command reference and a practical triage workflow.

## Install

```powershell
python -m pip install -r requirements.txt
```

Python 3.10 or newer is recommended. Run PowerShell as Administrator when inspecting protected processes; access restrictions are reported rather than bypassed.

## Features

- Inspect one process with detailed runtime information
- Filter process lists by name, user, status, or executable path
- Display recursive parent-to-descendant process trees
- Review active TCP and UDP connections
- Capture and compare process snapshots
- Calculate transparent heuristic suspicion scores
- Export JSON and CSV reports with host, OS, Python, timestamp, and SHA-256 metadata

## Use

```powershell
python .\pidsec.py 4242
python .\pidsec.py --list
python .\pidsec.py --list --name chrome
python .\pidsec.py --list --user SYSTEM
python .\pidsec.py --list --status running
python .\pidsec.py --list --path "Windows\\System32"
python .\pidsec.py --connections 4242
python .\pidsec.py --tree 4242
python .\pidsec.py 4242 --json .\reports\pid-4242.json
python .\pidsec.py --snapshot .\reports\before.json
python .\pidsec.py --compare .\reports\before.json
python .\pidsec.py --score
python .\pidsec.py --list --csv .\reports\processes.csv
python .\pidsec.py 4242 --csv .\reports\pid-4242.csv
python .\pidsec.py --interactive
```

`--tree` displays the selected process and its descendants recursively. Run from an elevated PowerShell session when inspecting protected processes. Windows can still deny access to kernel-protected or security-sensitive processes; PIDsec reports those fields as unavailable rather than bypassing the operating system.

JSON and CSV reports include the UTC timestamp, host, operating system, Python version, and executable SHA-256 when accessible. Snapshots record the running process set and can identify added, removed, restarted, or changed processes later. Suspicion scores are explainable heuristic indicators, not malware verdicts.

PIDsec is an inspection and triage tool, not a kernel syscall tracer. For syscall-level monitoring, pair it with an authorized tool such as Windows Performance Recorder, Sysmon, or a debugger.