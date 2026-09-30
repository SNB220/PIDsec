"""Windows process inspection CLI for DFIR, debugging, and IPC triage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shlex
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil. Install it with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)


APP_VERSION = "0.1.0"
AUTHOR = "SNB220"


def format_bytes(value: int | float | None) -> str:
    if value is None:
        return "n/a"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "n/a"


def format_time(value: float | None) -> str:
    if value is None:
        return "n/a"
    return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def safe_call(function: Any, default: Any = "access denied") -> Any:
    try:
        return function()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return default


def sha256_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as executable:
            for chunk in iter(lambda: executable.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def report_metadata() -> dict[str, str]:
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "author": AUTHOR,
    }


def endpoint(address: Any) -> str:
    if not address:
        return "-"
    host = getattr(address, "ip", address[0] if address else "?")
    port = getattr(address, "port", address[1] if len(address) > 1 else "?")
    return f"{host}:{port}"


def connection_record(connection: Any) -> dict[str, Any]:
    return {
        "family": str(getattr(connection, "family", "")),
        "type": str(getattr(connection, "type", "")),
        "local": endpoint(getattr(connection, "laddr", None)),
        "remote": endpoint(getattr(connection, "raddr", None)),
        "status": getattr(connection, "status", ""),
        "pid": getattr(connection, "pid", None),
    }


def collect_connections(pid: int | None = None) -> list[dict[str, Any]]:
    connections = safe_call(lambda: psutil.net_connections(kind="inet"), [])
    records = [connection_record(item) for item in connections]
    if pid is not None:
        records = [item for item in records if item["pid"] == pid]
    return sorted(records, key=lambda item: (item["local"], item["remote"]))


def process_snapshot_record(process: psutil.Process) -> dict[str, Any]:
    info = safe_call(lambda: process.as_dict(attrs=[
        "pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time"
    ]), {})
    return {
        "pid": info.get("pid", process.pid),
        "ppid": info.get("ppid"),
        "name": info.get("name"),
        "exe": info.get("exe"),
        "cmdline": info.get("cmdline") or [],
        "username": info.get("username"),
        "status": info.get("status"),
        "create_time": info.get("create_time"),
        "sha256": sha256_file(info.get("exe")),
    }


def collect_process_snapshot() -> list[dict[str, Any]]:
    records = []
    for process in psutil.process_iter():
        try:
            records.append(process_snapshot_record(process))
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue
    return sorted(records, key=lambda item: item["pid"])


def suspicion_score(record: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    executable = (record.get("exe") or "").casefold()
    command_line = " ".join(record.get("cmdline") or []).casefold()

    if any(marker in executable for marker in ("\\temp\\", "\\downloads\\", "\\public\\")):
        score += 2
        reasons.append("executable is in a commonly abused directory")
    if "\\appdata\\local\\temp\\" in executable:
        score += 2
        reasons.append("executable is in the user temporary directory")

    command_indicators = {
        "-enc": "encoded PowerShell argument",
        "-encodedcommand": "encoded PowerShell argument",
        "downloadstring": "PowerShell download command",
        "invoke-webrequest": "PowerShell web request",
        "certutil": "certificate utility in command line",
        "mshta": "HTML application host in command line",
        "rundll32": "DLL runner in command line",
        "regsvr32": "scriptable registration utility in command line",
        "bitsadmin": "BITS utility in command line",
    }
    for indicator, reason in command_indicators.items():
        if indicator in command_line:
            score += 2
            reasons.append(reason)

    return score, reasons


def print_scores(records: list[dict[str, Any]]) -> None:
    scored = []
    for record in records:
        score, reasons = suspicion_score(record)
        if score:
            scored.append((score, record, reasons))
    print(f"{'SCORE':>5}  {'PID':>7}  {'NAME':<28} REASONS")
    for score, record, reasons in sorted(scored, key=lambda item: (-item[0], item[1]["pid"])):
        print(f"{score:>5}  {record['pid']:>7}  {(record.get('name') or 'unknown')[:28]:<28} {'; '.join(reasons)}")
    if not scored:
        print("No suspicious indicators found.")


def write_snapshot(path: str) -> None:
    snapshot = {
        "schema_version": 1,
        **report_metadata(),
        "processes": collect_process_snapshot(),
    }
    with open(path, "w", encoding="utf-8") as snapshot_file:
        json.dump(snapshot, snapshot_file, indent=2)
    print(f"Wrote snapshot for {len(snapshot['processes'])} processes to {os.path.abspath(path)}")


def compare_snapshot(path: str) -> None:
    with open(path, encoding="utf-8") as snapshot_file:
        previous = json.load(snapshot_file)
    old_by_pid = {item["pid"]: item for item in previous.get("processes", [])}
    current_by_pid = {item["pid"]: item for item in collect_process_snapshot()}
    added = [current_by_pid[pid] for pid in current_by_pid.keys() - old_by_pid.keys()]
    removed = [old_by_pid[pid] for pid in old_by_pid.keys() - current_by_pid.keys()]
    restarted = []
    changed = []
    for pid in current_by_pid.keys() & old_by_pid.keys():
        current = current_by_pid[pid]
        old = old_by_pid[pid]
        if current.get("create_time") != old.get("create_time"):
            restarted.append(current)
        elif (current.get("exe"), current.get("cmdline"), current.get("status")) != (
            old.get("exe"), old.get("cmdline"), old.get("status")
        ):
            changed.append(current)

    print(f"Snapshot captured: {previous.get('captured_at', 'unknown')}")
    print(f"Added: {len(added)}  Removed: {len(removed)}  Restarted: {len(restarted)}  Changed: {len(changed)}")
    for title, records in (("Added", added), ("Removed", removed), ("Restarted", restarted), ("Changed", changed)):
        if records:
            print_section(title)
            for record in sorted(records, key=lambda item: item["pid"]):
                print(f"{record['pid']} {record.get('name') or 'unknown'}")


def process_record(process: psutil.Process, include_details: bool = True) -> dict[str, Any]:
    info = safe_call(lambda: process.as_dict(
        attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time", "num_threads"]
    ), {})
    record: dict[str, Any] = {
        "pid": info.get("pid", process.pid),
        "ppid": info.get("ppid"),
        "name": info.get("name"),
        "exe": info.get("exe"),
        "cmdline": info.get("cmdline"),
        "username": info.get("username"),
        "status": info.get("status"),
        "created": format_time(info.get("create_time")),
        "threads": info.get("num_threads"),
        "sha256": sha256_file(info.get("exe")),
    }
    if include_details:
        record.update({
            "memory": safe_call(lambda: {
                "rss": format_bytes(process.memory_info().rss),
                "vms": format_bytes(process.memory_info().vms),
            }),
            "cpu": safe_call(lambda: {
                "user_seconds": process.cpu_times().user,
                "system_seconds": process.cpu_times().system,
            }),
            "open_files": safe_call(lambda: [item.path for item in process.open_files()], []),
            "connections": collect_connections(process.pid),
            "children": safe_call(lambda: [child.pid for child in process.children(recursive=False)], []),
            "environment_available": safe_call(lambda: bool(process.environ()), False),
        })
    score, reasons = suspicion_score(record)
    record["suspicion"] = {"score": score, "reasons": reasons}
    return record


def print_section(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


def print_process(record: dict[str, Any]) -> None:
    print_section(f"Process {record.get('pid')} - {record.get('name') or 'unknown'}")
    for label, key in (("Executable", "exe"), ("Command line", "cmdline"), ("User", "username"),
                       ("Status", "status"), ("Created", "created"), ("Parent PID", "ppid"), ("Threads", "threads")):
        value = record.get(key)
        if isinstance(value, list):
            value = " ".join(value) if value else "n/a"
        print(f"{label:16} {value if value not in (None, '') else 'n/a'}")
    memory = record.get("memory", {})
    cpu = record.get("cpu", {})
    print(f"Memory RSS       {memory.get('rss', 'n/a')}")
    print(f"Memory VMS       {memory.get('vms', 'n/a')}")
    print(f"CPU time         user={cpu.get('user_seconds', 'n/a')}s system={cpu.get('system_seconds', 'n/a')}s")
    print(f"Environment      {'available' if record.get('environment_available') else 'restricted/unavailable'}")
    suspicion = record.get("suspicion", {})
    print(f"Suspicion score   {suspicion.get('score', 0)}")
    for reason in suspicion.get("reasons", []):
        print(f"  - {reason}")
    print_section("Network connections")
    print_connections(record.get("connections", []))
    print_section("Open files")
    for path in record.get("open_files", []) or ["none or access denied"]:
        print(path)
    print_section("Direct children")
    print(", ".join(map(str, record.get("children", []))) or "none")


def print_connections(records: list[dict[str, Any]]) -> None:
    if not records:
        print("No network connections found or access denied.")
        return
    print(f"{'PID':>7}  {'STATUS':<13} {'LOCAL':<28} {'REMOTE'}")
    for item in records:
        print(f"{str(item['pid']):>7}  {item['status']:<13} {item['local']:<28} {item['remote']}")


def write_csv(path: str, rows: list[dict[str, Any]]) -> None:
    if not path.casefold().endswith(".csv"):
        path += ".csv"
    fields = list(rows[0].keys()) if rows else ["captured_at", "host", "os", "python"]
    with open(path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote CSV report to {os.path.abspath(path)}")


def list_processes(name: str | None = None, user: str | None = None,
                   status: str | None = None, path: str | None = None,
                   csv_path: str | None = None) -> None:
    print(f"{'PID':>7}  {'PPID':>7}  {'NAME':<32} USER")
    processes = []
    for process in psutil.process_iter(["pid", "ppid", "name", "username", "status", "exe"]):
        try:
            info = process.info
            if name and name.casefold() not in (info.get("name") or "").casefold():
                continue
            if user and user.casefold() not in (info.get("username") or "").casefold():
                continue
            if status and status.casefold() != (info.get("status") or "").casefold():
                continue
            if path and path.casefold() not in (info.get("exe") or "").casefold():
                continue
            processes.append(info)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue
    for info in sorted(processes, key=lambda item: item["pid"]):
        name = (info.get("name") or "unknown")[:32]
        print(f"{info['pid']:>7}  {str(info.get('ppid') or '-'):>7}  {name:<32} {info.get('username') or '-'}")
    if csv_path:
        rows = []
        for info in processes:
            score, reasons = suspicion_score(info)
            rows.append({
                **report_metadata(),
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "sha256": sha256_file(info.get("exe")),
                "username": info.get("username"),
                "status": info.get("status"),
                "suspicion_score": score,
                "suspicion_reasons": "; ".join(reasons),
            })
        write_csv(csv_path, rows)


def print_tree(pid: int) -> None:
    root = psutil.Process(pid)
    visited: set[int] = set()

    def print_branch(process: psutil.Process, depth: int = 0) -> None:
        if process.pid in visited:
            return
        visited.add(process.pid)
        print(f"{'  ' * depth}{process.pid} {safe_call(process.name, 'unknown')}")
        children = safe_call(lambda: process.children(recursive=False), [])
        for child in sorted(children, key=lambda item: item.pid):
            print_branch(child, depth + 1)

    print_branch(root)


def help_menu() -> None:
    print(f"PIDsec - Windows process triage (Made by {AUTHOR})\n")
    print("Commands:")
    print("  pidsec.py <PID>                 Inspect one process")
    print("  pidsec.py --list                List running processes")
    print("  pidsec.py --list --name TEXT    Filter by process name")
    print("  pidsec.py --list --user TEXT    Filter by username")
    print("  pidsec.py --list --status TEXT  Filter by process status")
    print("  pidsec.py --list --path TEXT    Filter by executable path")
    print("  pidsec.py --connections [PID]  Show active TCP/UDP connections")
    print("  pidsec.py --tree PID            Show the recursive process tree")
    print("  pidsec.py PID --json FILE       Save a machine-readable report")
    print("  pidsec.py --snapshot FILE       Save a system process snapshot")
    print("  pidsec.py --compare FILE        Compare with a saved snapshot")
    print("  pidsec.py --score               Show suspicious-process scores")
    print("  pidsec.py --list --csv FILE     Export a process list as CSV")
    print("  pidsec.py --interactive         Open the command menu")
    print("\nProtected processes may hide command lines, files, environment data, or connections.")


def interactive() -> None:
    help_menu()
    while True:
        try:
            line = input("\npidsec> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            help_menu()
            continue
        command = shlex.split(line)
        name = command[0].casefold()
        if name in {"quit", "exit", "q"}:
            return
        if name in {"help", "?"}:
            help_menu()
            continue
        aliases = {
            "list": "--list",
            "connections": "--connections",
            "net": "--connections",
            "tree": "--tree",
            "score": "--score",
            "snapshot": "--snapshot",
            "compare": "--compare",
        }
        command[0] = aliases.get(name, command[0])
        try:
            args = build_parser().parse_args(command)
            if args.interactive:
                help_menu()
            else:
                run_args(args)
        except SystemExit:
            continue
        except (OSError, psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as error:
            print(f"Command failed: {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Windows process inspection for DFIR, debugging, and IPC triage. Made by {AUTHOR}."
    )
    parser.add_argument("pid", nargs="?", type=int, help="process ID to inspect")
    parser.add_argument("--list", action="store_true", help="list running processes")
    parser.add_argument("--name", help="filter listed processes by name")
    parser.add_argument("--user", help="filter listed processes by username")
    parser.add_argument("--status", help="filter listed processes by status")
    parser.add_argument("--path", help="filter listed processes by executable path")
    parser.add_argument("--connections", nargs="?", type=int, const=-1, metavar="PID", help="show active connections")
    parser.add_argument("--tree", type=int, metavar="PID", help="show the recursive process tree")
    parser.add_argument("--json", metavar="FILE", help="write a PID report as JSON")
    parser.add_argument("--csv", metavar="FILE", help="write process output as CSV")
    parser.add_argument("--snapshot", metavar="FILE", help="save a system process snapshot")
    parser.add_argument("--compare", metavar="FILE", help="compare current processes with a snapshot")
    parser.add_argument("--score", action="store_true", help="show suspicious-process scores")
    parser.add_argument("--interactive", action="store_true", help="open the interactive command menu")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION} (Made by {AUTHOR})")
    return parser


def run_args(args: argparse.Namespace) -> int:
    if args.snapshot:
        write_snapshot(args.snapshot)
        return 0
    if args.compare:
        try:
            compare_snapshot(args.compare)
            return 0
        except (OSError, json.JSONDecodeError) as error:
            print(f"Could not read snapshot: {error}", file=sys.stderr)
            return 1
    if args.score:
        print_scores(collect_process_snapshot())
        return 0
    if args.list:
        list_processes(args.name, args.user, args.status, args.path, args.csv)
        return 0
    if args.connections is not None:
        print_connections(collect_connections(None if args.connections == -1 else args.connections))
        return 0
    if args.tree is not None:
        try:
            print_tree(args.tree)
            return 0
        except (psutil.NoSuchProcess, ValueError):
            print(f"PID {args.tree} was not found.", file=sys.stderr)
            return 1
    if args.pid is None:
        help_menu()
        return 0
    try:
        record = process_record(psutil.Process(args.pid))
    except (psutil.NoSuchProcess, ValueError):
        print(f"PID {args.pid} was not found.", file=sys.stderr)
        return 1
    if args.json:
        record["report"] = report_metadata()
        with open(args.json, "w", encoding="utf-8") as report_file:
            json.dump(record, report_file, indent=2)
        print(f"Wrote report to {os.path.abspath(args.json)}")
    elif args.csv:
        suspicion = record.get("suspicion", {})
        write_csv(args.csv, [{
            **report_metadata(),
            "pid": record.get("pid"),
            "ppid": record.get("ppid"),
            "name": record.get("name"),
            "exe": record.get("exe"),
            "sha256": record.get("sha256"),
            "username": record.get("username"),
            "status": record.get("status"),
            "created": record.get("created"),
            "suspicion_score": suspicion.get("score", 0),
            "suspicion_reasons": "; ".join(suspicion.get("reasons", [])),
        }])
    else:
        print_process(record)
    return 0


def main() -> int:
    if platform.system() != "Windows":
        print("Warning: PIDsec is designed for Windows; some fields may be unavailable.", file=sys.stderr)
    args = build_parser().parse_args()
    if args.interactive or len(sys.argv) == 1:
        interactive()
        return 0
    return run_args(args)


if __name__ == "__main__":
    raise SystemExit(main())