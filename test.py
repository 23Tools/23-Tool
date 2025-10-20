#!/usr/bin/env python3
"""
extreme_perf_cli_pro.py

ExtremePerf CLI — Professional, modular Windows performance optimizer (safe-by-default)
- Hardware detection -> Recommendation engine -> Interactive selective apply
- Backup/Restore, Profiles, Dry-run, Logging, Apply manifest for targeted rollback
- Pure Python stdlib (no external deps)
- Safe: does not disable Defender/SmartScreen or modify security services
- Run as Administrator (script will relaunch elevated if not)

Usage:
    python extreme_perf_cli_pro.py          # interactive
    python extreme_perf_cli_pro.py --dry-run --recommended-only
    python extreme_perf_cli_pro.py --apply-recommended --yes
    python extreme_perf_cli_pro.py --profile profiles/gaming.json --yes

Author: Generated for user
Version: 1.0
"""

from __future__ import annotations
import os
import sys
import ctypes
import subprocess
import json
import time
import shutil
import argparse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

# -------------------------
# Basic config & globals
# -------------------------
VERSION = "1.0"
NOW = datetime.now().strftime("%Y%m%d_%H%M%S")
ROOT = Path.cwd()
BACKUP_DIR = ROOT / f"extreme_perf_backup_{NOW}"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = BACKUP_DIR / "extreme_perf.log"
MANIFEST_FILE = BACKUP_DIR / "apply_manifest.json"
HARDWARE_SNAPSHOT = BACKUP_DIR / "hardware_snapshot.json"
PROFILES_DIR = ROOT / "profiles"
PROFILES_DIR.mkdir(exist_ok=True)

# Default services & reg keys (conservative)
SERVICES = [
    "WSearch", "SysMain", "DiagTrack", "dmwappushservice", "RetailDemo",
    "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    "MapsBroker", "WMPNetworkSvc", "Fax", "W32Time", "wuauserv"
]
DISABLE_LIST = [
    "WSearch", "SysMain", "dmwappushservice", "RetailDemo",
    "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    "MapsBroker", "WMPNetworkSvc", "Fax"
]
REG_KEYS_TO_EXPORT = [
    r"HKEY_CURRENT_USER\Control Panel\Desktop",
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameBar"
]

# -------------------------
# Small helpers
# -------------------------
def ts() -> str:
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

def write_log(line: str) -> None:
    s = f"{ts()} {line}"
    print(s)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(s + "\n")
    except Exception:
        pass

def run_cmd(cmd: str, dry_run: bool = False, check: bool = False) -> Tuple[int, str]:
    write_log(f"CMD: {cmd}")
    if dry_run:
        return 0, "DRY_RUN"
    try:
        completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (completed.stdout or completed.stderr or "").strip()
        if check and completed.returncode != 0:
            raise RuntimeError(f"Command failed (rc={completed.returncode}): {out}")
        return completed.returncode, out
    except Exception as e:
        write_log(f"[ERROR] exception running command: {e}")
        return 1, str(e)

def require_admin(relaunch: bool = True) -> None:
    if not sys.platform.startswith("win"):
        write_log("This tool is for Windows only.")
        sys.exit(1)
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore
    except Exception:
        is_admin = False
    if not is_admin:
        if relaunch:
            write_log("Not running as Administrator — relaunching with elevation...")
            params = " ".join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
        else:
            write_log("Administrator privileges required.")
            sys.exit(1)

def save_json(obj: Any, path: Path) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
    except Exception as e:
        write_log(f"[WARN] Could not save JSON {path}: {e}")

def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# -------------------------
# Backup helpers
# -------------------------
def backup_services(dry_run: bool = False) -> Dict[str, str]:
    write_log("Backing up service start types...")
    svc_map: Dict[str, str] = {}
    for s in SERVICES:
        cmd = f'powershell -Command "Try {{(Get-Service -Name \\"{s}\\" -ErrorAction Stop).StartType}} Catch {{ Write-Output \\"MISSING\\" }}"'
        rc, out = run_cmd(cmd, dry_run=dry_run)
        svc_map[s] = (out.strip() or "UNKNOWN")
    save_json(svc_map, BACKUP_DIR / "services_backup.json")
    write_log(f"Services backup saved -> {BACKUP_DIR/'services_backup.json'}")
    return svc_map

def backup_registry(dry_run: bool = False) -> None:
    write_log("Backing up registry keys (best-effort)...")
    for i, key in enumerate(REG_KEYS_TO_EXPORT):
        outfile = BACKUP_DIR / f"reg_backup_{i}.reg"
        cmd = f'reg export "{key}" "{outfile}" /y'
        rc, out = run_cmd(cmd, dry_run=dry_run)
        if rc == 0:
            write_log(f"Exported {key} -> {outfile.name}")
        else:
            write_log(f"Could not export {key} (may not exist): {out}")
    write_log("Registry backup attempt complete.")

# -------------------------
# Hardware detection
# -------------------------
def detect_cpu(dry_run: bool = False) -> Dict[str, Any]:
    cpu = {"Name": "UNKNOWN", "Cores": None, "LogicalProcessors": None, "MaxClockMHz": None}
    rc, out = run_cmd('wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed /format:csv', dry_run=dry_run)
    if rc == 0 and out and "Name" in out:
        try:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) >= 2:
                cols = lines[0].split(',')
                vals = lines[1].split(',')
                mapping = dict(zip(cols, vals))
                cpu["Name"] = mapping.get("Name", cpu["Name"])
                try:
                    cpu["Cores"] = int(mapping.get("NumberOfCores") or 0)
                    cpu["LogicalProcessors"] = int(mapping.get("NumberOfLogicalProcessors") or 0)
                    cpu["MaxClockMHz"] = int(mapping.get("MaxClockSpeed") or 0)
                except Exception:
                    pass
        except Exception:
            pass
    else:
        rc2, out2 = run_cmd('wmic cpu get name', dry_run=dry_run)
        if rc2 == 0:
            parts = [l.strip() for l in out2.splitlines() if l.strip()]
            if len(parts) >= 2:
                cpu["Name"] = parts[1]
    return cpu

def detect_gpu(dry_run: bool = False) -> List[Dict[str, Any]]:
    gpus: List[Dict[str, Any]] = []
    rc, out = run_cmd('wmic path win32_VideoController get Name,AdapterRAM /format:csv', dry_run=dry_run)
    if rc == 0 and out and "Name" in out:
        try:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            cols = lines[0].split(',')
            for line in lines[1:]:
                vals = line.split(',')
                mapping = dict(zip(cols, vals))
                name = mapping.get("Name") or "UNKNOWN"
                ram = mapping.get("AdapterRAM") or ""
                gpus.append({"Name": name, "AdapterRAM": ram})
        except Exception:
            pass
    else:
        rc2, out2 = run_cmd('powershell -Command "Get-CimInstance Win32_VideoController | Select-Object -Property Name | ConvertTo-Json"', dry_run=dry_run)
        if rc2 == 0 and out2:
            try:
                parsed = json.loads(out2)
                if isinstance(parsed, list):
                    for item in parsed:
                        gpus.append({"Name": item.get("Name")})
                elif isinstance(parsed, dict):
                    gpus.append({"Name": parsed.get("Name")})
            except Exception:
                pass
    return gpus

def detect_memory(dry_run: bool = False) -> Dict[str, Any]:
    mem = {"TotalMB": None}
    rc, out = run_cmd('wmic computersystem get TotalPhysicalMemory /format:csv', dry_run=dry_run)
    if rc == 0 and out:
        try:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) >= 2:
                cols = lines[0].split(',')
                vals = lines[1].split(',')
                mapping = dict(zip(cols, vals))
                total = int(mapping.get("TotalPhysicalMemory") or 0)
                mem["TotalMB"] = total // (1024 * 1024)
        except Exception:
            pass
    return mem

def detect_disks(dry_run: bool = False) -> List[Dict[str, Any]]:
    disks: List[Dict[str, Any]] = []
    rc, out = run_cmd('wmic diskdrive get Model,InterfaceType,MediaType,Size /format:csv', dry_run=dry_run)
    if rc == 0 and out and "Model" in out:
        try:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            cols = lines[0].split(',')
            for line in lines[1:]:
                vals = line.split(',')
                mapping = dict(zip(cols, vals))
                model = mapping.get("Model") or "UNKNOWN"
                interface = mapping.get("InterfaceType") or ""
                mediatype = mapping.get("MediaType") or ""
                size = mapping.get("Size") or ""
                size_gb = None
                try:
                    size_gb = int(size) // (1024**3) if size else None
                except Exception:
                    size_gb = None
                disks.append({"Model": model, "Interface": interface, "MediaType": mediatype, "SizeGB": size_gb})
        except Exception:
            pass
    return disks

def detect_os_and_power(dry_run: bool = False) -> Dict[str, Any]:
    info = {"OS": "Windows", "Build": None, "PowerPlan": None}
    rc, out = run_cmd('wmic os get Caption,Version /format:csv', dry_run=dry_run)
    if rc == 0 and out:
        try:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) >= 2:
                cols = lines[0].split(',')
                vals = lines[1].split(',')
                mapping = dict(zip(cols, vals))
                info["OS"] = mapping.get("Caption") or "Windows"
                info["Build"] = mapping.get("Version")
        except Exception:
            pass
    rc2, out2 = run_cmd("powercfg /getactivescheme", dry_run=dry_run)
    if rc2 == 0 and out2:
        info["PowerPlan"] = out2.strip()
    return info

def detect_hardware(dry_run: bool = False) -> Dict[str, Any]:
    write_log("Detecting hardware...")
    hw = {}
    hw["CPU"] = detect_cpu(dry_run=dry_run)
    hw["GPU"] = detect_gpu(dry_run=dry_run)
    hw["Memory"] = detect_memory(dry_run=dry_run)
    hw["Disks"] = detect_disks(dry_run=dry_run)
    hw["OS"] = detect_os_and_power(dry_run=dry_run)
    save_json(hw, HARDWARE_SNAPSHOT)
    write_log(f"Hardware snapshot saved -> {HARDWARE_SNAPSHOT}")
    return hw

# -------------------------
# Recommendation engine
# -------------------------
# Each recommendation is a dict with fields:
# id (str), category (str), title (str), priority (High/Medium/Low),
# risk (None/Low/Moderate/High), reversible (bool), why (str),
# commands (list[str]) - commands to run (for dry-run preview),
# apply_fn (callable) - function to run for actual apply.
Recommendation = Dict[str, Any]

def build_recommendations(hw: Dict[str, Any], dry_run: bool = False) -> List[Recommendation]:
    recs: List[Recommendation] = []
    # Helper to append
    def add_rec(r: Recommendation) -> None:
        recs.append(r)
    # 1) Power plan recommendation
    power = hw.get("OS", {}).get("PowerPlan", "") or ""
    if "Ultimate" in power or "Ultimate Performance" in power:
        add_rec({
            "id": "power_plan_ok",
            "category": "Power",
            "title": "Ultimate Performance power plan already active",
            "priority": "Low",
            "risk": "None",
            "reversible": True,
            "why": "Your system already uses Ultimate Performance or equivalent.",
            "commands": [],
            "apply_fn": lambda dry_run: (0, "Already active")
        })
    else:
        add_rec({
            "id": "power_plan_enable",
            "category": "Power",
            "title": "Activate Ultimate Performance power plan (or High Performance fallback)",
            "priority": "High",
            "risk": "Low",
            "reversible": True,
            "why": "Reduces power management throttling; beneficial for desktops and gaming systems. Laptops may reduce battery life.",
            "commands": [
                "powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 || true",
                "powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 || powercfg -setactive SCHEME_MIN"
            ],
            "apply_fn": lambda dry_run: apply_power_plan(dry_run)
        })
    # 2) CPU min/max on AC (detect laptop vs desktop)
    cpu = hw.get("CPU", {}) or {}
    mem_mb = hw.get("Memory", {}).get("TotalMB") or 0
    is_laptop = False
    # best-effort detection: presence of "Battery" or check model? We'll just ask: if power plan mentions "Battery" not available; fallback: assume desktop when memory >= 16000 and name doesn't include 'mobile' - this is heuristic
    cpu_name = cpu.get("Name", "") or ""
    if "mobile" in cpu_name.lower() or cpu_name.lower().find("u") != -1 and "intel" in cpu_name.lower():
        is_laptop = True
    # better heuristic: check for battery via powercfg -devicequery
    rc, out = run_cmd("WMIC Path Win32_Battery Get BatteryStatus", dry_run=dry_run)
    if rc == 0 and out and any(char.isdigit() for char in out):
        # if battery info present, mark laptop
        is_laptop = True
    if not is_laptop:
        add_rec({
            "id": "cpu_minmax_100",
            "category": "Hardware",
            "title": "Set CPU min/max to 100% while on AC (reduce OS throttling)",
            "priority": "High",
            "risk": "Low",
            "reversible": True,
            "why": "Prevents OS from reducing processor speed on desktops and gaming rigs; laptops may risk heat/battery impact.",
            "commands": [
                "powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100",
                "powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100",
                "powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2",
                "powercfg /SETACTIVE SCHEME_CURRENT"
            ],
            "apply_fn": lambda dry_run: set_processor_power_limits(dry_run)
        })
    else:
        add_rec({
            "id": "cpu_balanced_laptop",
            "category": "Hardware",
            "title": "Keep CPU conservative on laptops (skip forcing 100% min)",
            "priority": "Medium",
            "risk": "None",
            "reversible": True,
            "why": "Laptops are thermally and power constrained; forcing 100% min is not recommended.",
            "commands": [],
            "apply_fn": lambda dry_run: (0, "Skipped for laptops")
        })
    # 3) Visual effects
    add_rec({
        "id": "visual_best_performance",
        "category": "Visual",
        "title": "Set visual effects to 'Adjust for best performance'",
        "priority": "Medium",
        "risk": "None",
        "reversible": True,
        "why": "Disables many UI animations to reduce background GPU/CPU usage.",
        "commands": [
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f',
            r'reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f'
        ],
        "apply_fn": lambda dry_run: visual_effects_best_performance(dry_run)
    })
    # 4) Services
    add_rec({
        "id": "service_aggressive_disable",
        "category": "Services",
        "title": "Disable common non-security background services (indexer, superfetch, xbox services)",
        "priority": "High" if mem_mb >= 8000 else "Medium",
        "risk": "Low",
        "reversible": True,
        "why": "Removes background work that can cause disk/CPU usage; beneficial for systems with less memory or gaming focus.",
        "commands": [f"sc stop {s} && sc config {s} start= disabled" for s in DISABLE_LIST],
        "apply_fn": lambda dry_run: apply_service_tweaks(dry_run)
    })
    # 5) Network
    add_rec({
        "id": "network_low_latency",
        "category": "Network",
        "title": "Apply network low-latency tweaks (TCP autotune normal, disable heuristics)",
        "priority": "Medium",
        "risk": "Low",
        "reversible": True,
        "why": "Improves latency for online games and streaming; some legacy apps may not expect changed TCP stack behavior.",
        "commands": [
            "netsh int tcp set global autotuninglevel=normal",
            "netsh int tcp set heuristics disabled",
            "netsh int tcp set global rss=enabled",
            "ipconfig /flushdns",
            "netsh winsock reset"
        ],
        "apply_fn": lambda dry_run: network_low_latency(dry_run)
    })
    # 6) Game Mode & GameBar
    add_rec({
        "id": "game_mode_gamebar",
        "category": "Gaming",
        "title": "Enable Game Mode, disable Game Bar / Game DVR overlays",
        "priority": "Medium",
        "risk": "Low",
        "reversible": True,
        "why": "Game Mode can reduce interference; GameBar/DVR overlays can add overhead.",
        "commands": [
            r'reg add "HKLM\SOFTWARE\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f',
            r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f'
        ],
        "apply_fn": lambda dry_run: game_mode_and_gamebar(dry_run)
    })
    # 7) Background apps and tips
    add_rec({
        "id": "background_and_tips",
        "category": "Privacy/Background",
        "title": "Disable background apps and Windows tips/suggestions",
        "priority": "Low",
        "risk": "None",
        "reversible": True,
        "why": "Reduces background tasks and notifications which can interrupt gaming or heavy workloads.",
        "commands": [
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f',
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f'
        ],
        "apply_fn": lambda dry_run: (background_apps_disable(dry_run), notifications_and_tips_disable(dry_run))[0]
    })
    # 8) SSD/NVMe guidance (not automatic)
    disks = hw.get("Disks", []) or []
    nvme_count = sum(1 for d in disks if (d.get("Interface") or "").upper().find("NVME") != -1 or ("SSD" in (d.get("MediaType") or "").upper()))
    if nvme_count > 0:
        add_rec({
            "id": "ssd_guidance",
            "category": "Storage",
            "title": "NVMe/SSD detected — guidance: ensure TRIM and latest NVMe driver",
            "priority": "Low",
            "risk": "None",
            "reversible": True,
            "why": "Windows typically handles TRIM automatically; driver updates can improve performance and reliability.",
            "commands": [],
            "apply_fn": lambda dry_run: (0, "Guidance only; no changes applied")
        })
    # 9) Power cooling policy
    add_rec({
        "id": "cooling_policy_active",
        "category": "Hardware",
        "title": "Set active cooling policy (if supported)",
        "priority": "Medium",
        "risk": "Low",
        "reversible": True,
        "why": "Encourages fans to increase before throttling, improving performance at the cost of noise.",
        "commands": [
            'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR SYSTEMCOOLINGPOLICY 0',
            'powercfg /SETACTIVE SCHEME_CURRENT'
        ],
        "apply_fn": lambda dry_run: set_active_cooling_policy(dry_run)
    })
    # Additional recommendations may be appended based on future detection heuristics
    return recs

# -------------------------
# Action implementations
# -------------------------
def apply_power_plan(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Applying Ultimate Performance (or fallback) ...")
    rc, out = run_cmd("powercfg -list", dry_run=dry_run)
    if dry_run:
        return 0, "DRY_RUN"
    if "Ultimate" in out or "e9a42b02-d5df-448d-aa00-03f14749eb61" in out:
        run_cmd("powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61", dry_run=dry_run)
        return 0, "Activated"
    # try duplicate and set
    run_cmd("powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61", dry_run=dry_run)
    run_cmd("powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61", dry_run=dry_run)
    # fallback
    run_cmd("powercfg -setactive SCHEME_MIN", dry_run=dry_run)
    return 0, "Fallback applied"

def set_processor_power_limits(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Setting CPU AC min/max/boost values (best-effort)...")
    cmds = [
        'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100',
        'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100',
        'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2',
        'powercfg /SETACTIVE SCHEME_CURRENT'
    ]
    results = []
    for c in cmds:
        rc, out = run_cmd(c, dry_run=dry_run)
        results.append((rc, out))
    # Return success if at least one succeeded
    success = any(rc == 0 for rc, _ in results)
    return (0, "Commands attempted") if success else (1, "Commands failed or unsupported")

def set_active_cooling_policy(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Setting cooling policy to active (best-effort)...")
    cmds = [
        'powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR SYSTEMCOOLINGPOLICY 0',
        'powercfg /SETACTIVE SCHEME_CURRENT'
    ]
    ok = False
    for c in cmds:
        rc, out = run_cmd(c, dry_run=dry_run)
        if rc == 0:
            ok = True
    return (0, "Applied" if ok else "Unsupported")

def visual_effects_best_performance(dry_run: bool = False) -> Tuple[int, str]:
    cmds = [
        r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f',
        r'reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f',
        r'reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f',
        r'reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f'
    ]
    ok = False
    for c in cmds:
        rc, out = run_cmd(c, dry_run=dry_run)
        if rc == 0:
            ok = True
    return (0, "Applied" if ok else "Failed")

def apply_service_tweaks(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Applying service tweaks (disabling non-security services)...")
    for s in DISABLE_LIST:
        run_cmd(f"sc stop {s}", dry_run=dry_run)
        run_cmd(f"sc config {s} start= disabled", dry_run=dry_run)
    # Set Windows Update to manual (best-effort)
    run_cmd("sc config wuauserv start= demand", dry_run=dry_run)
    run_cmd("sc config W32Time start= demand", dry_run=dry_run)
    return (0, "Service tweaks attempted")

def clean_temp_and_update_cache(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Cleaning TEMP and update caches (best-effort)...")
    temp_paths = [
        os.getenv("TEMP"),
        os.path.join(os.getenv("SYSTEMROOT") or "C:\\Windows", "Temp"),
        os.path.join(os.getenv("SYSTEMROOT") or "C:\\Windows", "SoftwareDistribution", "Download"),
        os.path.join(os.getenv("SYSTEMROOT") or "C:\\Windows", "Prefetch")
    ]
    for p in temp_paths:
        if not p:
            continue
        if dry_run:
            write_log(f"[dry] Would clean: {p}")
            continue
        try:
            for root, dirs, files in os.walk(p):
                for f in files:
                    try:
                        os.remove(os.path.join(root, f))
                    except Exception:
                        pass
                for d in dirs:
                    try:
                        shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                    except Exception:
                        pass
        except Exception as e:
            write_log(f"[WARN] Cleaning {p}: {e}")
    run_cmd("cleanmgr /sagerun:1", dry_run=dry_run)
    return (0, "Cleanup attempted")

def network_low_latency(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Applying network tweaks...")
    cmds = [
        "netsh int tcp set global autotuninglevel=normal",
        "netsh int tcp set heuristics disabled",
        "netsh int tcp set global rss=enabled",
        "ipconfig /flushdns",
        "netsh winsock reset"
    ]
    ok = False
    for c in cmds:
        rc, out = run_cmd(c, dry_run=dry_run)
        if rc == 0:
            ok = True
    return (0, "Network tweaks applied" if ok else "Network tweak failures")

def game_mode_and_gamebar(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Toggling Game Mode / Game Bar settings...")
    cmds = [
        r'reg add "HKLM\SOFTWARE\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f',
        r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f',
        r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f',
        r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameBar" /v AudioCaptureEnabled /t REG_DWORD /d 0 /f'
    ]
    ok = False
    for c in cmds:
        rc, out = run_cmd(c, dry_run=dry_run)
        if rc == 0:
            ok = True
    return (0, "Game mode & gamebar toggles applied" if ok else "Failed")

def background_apps_disable(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Disabling background apps (current user)...")
    run_cmd(r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f', dry_run=dry_run)
    run_cmd(r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f', dry_run=dry_run)
    return (0, "Background apps disabled")

def notifications_and_tips_disable(dry_run: bool = False) -> Tuple[int, str]:
    write_log("Disabling notifications/tips...")
    run_cmd(r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f', dry_run=dry_run)
    run_cmd(r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f', dry_run=dry_run)
    return (0, "Notifications & tips disabled")

# -------------------------
# Apply / Manifest / Restore
# -------------------------
def record_manifest_entry(manifest: Dict[str, Any], rec: Recommendation, result: Tuple[int, str]) -> None:
    entry = {
        "id": rec.get("id"),
        "title": rec.get("title"),
        "category": rec.get("category"),
        "timestamp": datetime.now().isoformat(),
        "result": {"rc": result[0], "out": result[1]}
    }
    manifest.setdefault("applied", []).append(entry)
    save_json(manifest, MANIFEST_FILE)

def restore_from_backup(dry_run: bool = False) -> None:
    write_log("Restoring services and registry from backup (best-effort)...")
    # services
    svc_backup = load_json(BACKUP_DIR / "services_backup.json")
    if svc_backup:
        for svc, val in svc_backup.items():
            v = str(val).upper()
            if v.startswith("AUTO"):
                run_cmd(f"sc config {svc} start= auto", dry_run=dry_run)
                run_cmd(f"sc start {svc}", dry_run=dry_run)
            elif v in ("MANUAL", "DEMAND"):
                run_cmd(f"sc config {svc} start= demand", dry_run=dry_run)
            elif v == "DISABLED":
                run_cmd(f"sc config {svc} start= disabled", dry_run=dry_run)
    # registry imports
    for file in BACKUP_DIR.glob("reg_backup_*.reg"):
        run_cmd(f'reg import "{file}"', dry_run=dry_run)
    write_log("Restore attempted. Reboot may be required to fully revert.")

# -------------------------
# Profiles (sample load/save)
# -------------------------
def load_profile(path: Path) -> Optional[Dict[str, Any]]:
    p = load_json(path)
    if not p:
        write_log(f"[WARN] Could not load profile: {path}")
    return p

def save_profile(profile: Dict[str, Any], path: Path) -> None:
    save_json(profile, path)
    write_log(f"Saved profile -> {path}")

# -------------------------
# Interactive UI (CLI)
# -------------------------
def print_header():
    print("="*60)
    print(f"ExtremePerf CLI v{VERSION} — Backup folder: {BACKUP_DIR}")
    print("="*60)

def show_recommendations(recs: List[Recommendation]) -> None:
    print("\nRecommendations:")
    for i, r in enumerate(recs, start=1):
        print(f"[{i}] [{r['category']}] {r['title']}  (Priority: {r['priority']}; Risk: {r['risk']})")
        print(f"     Why: {r['why']}")
    print("")

def pick_indices(prompt: str, max_i: int) -> List[int]:
    s = input(prompt).strip()
    if not s:
        return []
    if s.lower() in ("a", "all"):
        return list(range(1, max_i+1))
    parts = []
    for token in s.replace(",", " ").split():
        try:
            n = int(token)
            if 1 <= n <= max_i:
                parts.append(n)
        except Exception:
            pass
    return sorted(set(parts))

def apply_selected(recs: List[Recommendation], indices: List[int], dry_run: bool, manifest: Dict[str, Any]):
    for idx in indices:
        r = recs[idx-1]
        write_log(f"Applying: {r['title']} (id={r['id']})")
        try:
            # call apply_fn which returns Tuple[int,str] or (None)
            fn = r.get("apply_fn")
            if callable(fn):
                result = fn(dry_run)
                if isinstance(result, tuple):
                    rc, out = result
                else:
                    rc, out = 0, str(result)
            else:
                # fallback: run commands list
                rc = 0
                out = ""
                for c in r.get("commands", []):
                    c_rc, c_out = run_cmd(c, dry_run=dry_run)
                    if c_rc != 0:
                        rc = c_rc
                    out += f"\n{c_out}"
            write_log(f"Result: rc={rc}; out={out}")
            record_manifest_entry(manifest, r, (rc, out))
        except Exception as e:
            write_log(f"[ERROR] Applying {r['id']}: {e}")
            record_manifest_entry(manifest, r, (1, str(e)))

# -------------------------
# Main flows
# -------------------------
def interactive_flow(args):
    require_admin()
    print_header()
    dry_run = args.dry_run
    # detect hardware
    hw = detect_hardware(dry_run=dry_run)
    recs = build_recommendations(hw, dry_run=dry_run)
    manifest = {"timestamp": datetime.now().isoformat(), "hw_snapshot": str(HARDWARE_SNAPSHOT), "applied": []}
    save_json(manifest, MANIFEST_FILE)
    # show recommended prioritized view
    show_recommendations(recs)
    # menu
    while True:
        print("\nMenu:")
        print("[1] Show recommendations")
        print("[2] Apply recommended (interactive toggles)")
        print("[3] Apply specific recommendations by number")
        print("[4] Show categories")
        print("[5] Backup current settings (services + registry)")
        print("[6] Restore from last backup (best-effort)")
        print("[7] Apply ALL recommendations (non-interactive)")
        print("[8] Manage profiles (load/save)")
        print("[0] Exit")
        choice = input("Select: ").strip()
        if choice == "1":
            show_recommendations(recs)
        elif choice == "2":
            # interactive toggle: show each recommended and ask yes/no
            to_apply = []
            for i, r in enumerate(recs, start=1):
                ans = input(f"Apply [{i}] {r['title']}? (y/N): ").strip().lower()
                if ans in ("y", "yes"):
                    to_apply.append(i)
            if to_apply:
                apply_selected(recs, to_apply, dry_run=dry_run, manifest=manifest)
                save_json(manifest, MANIFEST_FILE)
            else:
                print("No recommendations selected.")
        elif choice == "3":
            show_recommendations(recs)
            indices = pick_indices("Enter numbers (e.g. 1 3 5 or 'all'): ", len(recs))
            if indices:
                apply_selected(recs, indices, dry_run=dry_run, manifest=manifest)
                save_json(manifest, MANIFEST_FILE)
        elif choice == "4":
            cats = {}
            for i, r in enumerate(recs, start=1):
                cats.setdefault(r["category"], []).append((i, r["title"], r["priority"]))
            for cat, items in cats.items():
                print(f"\nCategory: {cat}")
                for it in items:
                    print(f"  [{it[0]}] {it[1]} (Priority: {it[2]})")
        elif choice == "5":
            backup_services(dry_run=dry_run)
            backup_registry(dry_run=dry_run)
            print(f"Backups saved to: {BACKUP_DIR}")
        elif choice == "6":
            ok = input("This will attempt to restore services/registry from backups. Continue? (y/N): ").strip().lower()
            if ok in ("y", "yes"):
                restore_from_backup(dry_run=dry_run)
        elif choice == "7":
            indices = list(range(1, len(recs)+1))
            apply_selected(recs, indices, dry_run=dry_run, manifest=manifest)
            save_json(manifest, MANIFEST_FILE)
        elif choice == "8":
            manage_profiles_menu(recs, manifest, dry_run)
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid selection.")

def manage_profiles_menu(recs, manifest, dry_run):
    print("\nProfiles:")
    print("[1] List built-in sample profiles")
    print("[2] Load profile from file and apply")
    print("[3] Save current recommended set as profile")
    print("[0] Back")
    c = input("Select: ").strip()
    if c == "1":
        list_sample_profiles()
    elif c == "2":
        p = input("Enter profile path (relative or full): ").strip()
        if p:
            prof = load_profile(Path(p))
            if prof:
                apply_profile(prof, dry_run, manifest)
    elif c == "3":
        name = input("Profile name (no spaces): ").strip()
        if name:
            prof = {"name": name, "created": datetime.now().isoformat(), "recommended_ids": [r["id"] for r in recs]}
            save_profile(prof, PROFILES_DIR / f"{name}.json")
    else:
        return

def list_sample_profiles():
    print("\nSample profiles in 'profiles/' directory:")
    for p in PROFILES_DIR.glob("*.json"):
        print(f" - {p.name}")
    print("You can edit them or create your own JSON profiles.")

def apply_profile(profile: Dict[str, Any], dry_run: bool, manifest: Dict[str, Any]) -> None:
    ids = profile.get("recommended_ids") or []
    if not ids:
        write_log("[WARN] Profile has no recommendations to apply.")
        return
    # rebuild recommendations to map
    hw = load_json(HARDWARE_SNAPSHOT) or detect_hardware(dry_run=dry_run)
    recs = build_recommendations(hw, dry_run=dry_run)
    id_to_index = {r["id"]: i+1 for i, r in enumerate(recs)}
    indices = [id_to_index[i] for i in ids if i in id_to_index]
    write_log(f"Applying profile '{profile.get('name')}' -> indices: {indices}")
    apply_selected(recs, indices, dry_run=dry_run, manifest=manifest)

# -------------------------
# CLI entrypoint
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="ExtremePerf CLI Pro - Intelligent Windows performance optimizer (safe)")
    p.add_argument("--dry-run", action="store_true", help="Do not apply changes; show commands and recommendations.")
    p.add_argument("--recommended-only", action="store_true", help="Show recommended actions and exit.")
    p.add_argument("--apply-recommended", action="store_true", help="Apply recommended actions non-interactively (requires --yes to skip prompts).")
    p.add_argument("--profile", type=str, help="Path to profile JSON to apply.")
    p.add_argument("--backup-only", action="store_true", help="Only perform backup (services + reg) and exit.")
    p.add_argument("--restore", action="store_true", help="Restore from backup.")
    p.add_argument("--yes", action="store_true", help="Assume yes to prompts (use with caution).")
    return p.parse_args()

def main():
    args = parse_args()
    require_admin()
    print_header()
    if args.backup_only:
        backup_services(dry_run=args.dry_run)
        backup_registry(dry_run=args.dry_run)
        print(f"Backups saved to {BACKUP_DIR}")
        return
    if args.restore:
        if not args.yes:
            ans = input("Restore from backups in {}? (y/N): ".format(BACKUP_DIR)).strip().lower()
            if ans not in ("y", "yes"):
                print("Restore cancelled.")
                return
        restore_from_backup(dry_run=args.dry_run)
        return
    # Detect hardware & build recommendation list
    hw = detect_hardware(dry_run=args.dry_run)
    recommendations = build_recommendations(hw, dry_run=args.dry_run)
    save_json(recommendations, BACKUP_DIR / "recommendations.json")
    # Show recommended only?
    if args.recommended_only:
        show_recommendations(recommendations)
        return
    # Apply profile if provided
    manifest = {"timestamp": datetime.now().isoformat(), "hw_snapshot": str(HARDWARE_SNAPSHOT), "applied": []}
    save_json(manifest, MANIFEST_FILE)
    if args.profile:
        prof = load_profile(Path(args.profile))
        if not prof:
            print("Could not load profile:", args.profile)
            return
        apply_profile(prof, args.dry_run, manifest)
        print("Profile application complete.")
        return
    # Non-interactive apply recommended
    if args.apply_recommended:
        if not args.yes:
            ans = input("Apply recommended actions non-interactively? (y/N): ").strip().lower()
            if ans not in ("y", "yes"):
                print("Cancelled.")
                return
        # pick high/medium priority by default
        to_apply = [i+1 for i, r in enumerate(recommendations) if r["priority"] in ("High", "Medium")]
        apply_selected(recommendations, to_apply, dry_run=args.dry_run, manifest=manifest)
        print("Recommended actions attempted; see log & manifest.")
        return
    # Fall back to interactive menu
    interactive_flow(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        write_log("Interrupted by user.")
    except Exception as e:
        write_log(f"[FATAL] Unhandled exception: {e}")
        raise
