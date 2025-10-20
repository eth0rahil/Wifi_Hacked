#!/usr/bin/env python3
"""
scan_real_fake_attack_colored_labels_v2.py

- REAL Wi-Fi scan (netsh / nmcli / iwlist / airport).
- FAKE attack sequence (prints simulated steps only).
- Replaced the color-word menu with the requested bold-green notice:
  "Md Rahil Sheikh Raj. Use For Only Entertaintment Purpose. Use wlan0 for Good Experience."
- Use only on networks you own or have explicit permission to scan.
"""

import platform
import subprocess
import re
import sys
import shutil
import time
import random
from colorama import init, Fore, Style

init(autoreset=True)

RED_BANNER = r"""
 █     █░ ██▓  █████▒██▓    ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀▓█████ ▓█████▄ 
▓█░ █ ░█░▓██▒▓██   ▒▓██▒   ▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▒██▀ ██▌
▒█░ █ ░█ ▒██▒▒████ ░▒██▒   ▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ░██   █▌
░█░ █ ░█ ░██░░▓█▒  ░░██░   ░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ░▓█▄   ▌
░░██▒██▓ ░██░░▒█░   ░██░   ░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░▒████▓ 
░ ▓░▒ ▒  ░▓   ▒ ░   ░▓      ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░ ▒▒▓  ▒ 
  ▒ ░ ░   ▒ ░ ░      ▒ ░    ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░ ░ ▒  ▒ 
  ░   ░   ▒ ░ ░ ░    ▒ ░    ░  ░░ ░  ░   ▒   ░        ░ ░░ ░    ░    ░ ░  ░ 
    ░     ░          ░      ░  ░  ░      ░  ░░ ░      ░  ░      ░  ░   ░    
                                             ░                       ░      
"""

# color approximations
COLOR_YELLOW = Fore.YELLOW + Style.BRIGHT
COLOR_ORANGE = Fore.LIGHTYELLOW_EX + Style.BRIGHT  # approximate orange
COLOR_PINK = Fore.MAGENTA + Style.BRIGHT            # approximate pink
COLOR_GREEN = Fore.GREEN + Style.BRIGHT
COLOR_WHITE = Fore.WHITE + Style.BRIGHT

def run_cmd(cmd):
    try:
        p = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return p.stdout
    except subprocess.CalledProcessError as e:
        return (e.stdout or "") + "\n" + (e.stderr or "")

#######################
# Parsers for outputs #
#######################

def parse_netsh(output):
    networks = []
    ssid = None; bssid = None; signal = None; auth = None
    for raw in output.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID\s+\d+\s+:\s+(.*)$", line)
        if m:
            if ssid:
                networks.append({"ssid": ssid, "bssid": bssid or "", "signal": signal or "", "auth": auth or ""})
                bssid = None; signal = None; auth = None
            ssid = m.group(1)
            continue
        m = re.match(r"^BSSID\s+\d+\s+:\s+([0-9a-fA-F:-]{17})", line)
        if m:
            bssid = m.group(1); continue
        m = re.match(r"^Signal\s+:\s+(\d+)%", line)
        if m:
            signal = m.group(1) + "%"; continue
        m = re.match(r"^Authentication\s+:\s+(.*)$", line)
        if m:
            auth = m.group(1); continue
    if ssid:
        networks.append({"ssid": ssid, "bssid": bssid or "", "signal": signal or "", "auth": auth or ""})
    return networks

def parse_nmcli(output):
    networks = []
    for line in output.splitlines():
        if not line.strip(): continue
        parts = line.split(":")
        if len(parts) >= 4:
            ssid = ":".join(parts[:-3])
            signal = parts[-3]
            security = parts[-2]
            bssid = parts[-1]
            networks.append({"ssid": ssid, "bssid": bssid, "signal": (signal + "%"), "auth": security})
        else:
            tokens = line.split()
            if tokens:
                networks.append({"ssid": tokens[0], "bssid": "", "signal": "", "auth": " ".join(tokens[1:])})
    return networks

def parse_airport(output):
    networks = []
    for line in output.splitlines():
        if not line.strip(): continue
        if re.match(r"^\s*SSID\s+", line): continue
        m = re.search(r"([0-9A-Fa-f:]{17})\s+(-?\d+)\s+(.+)$", line)
        if m:
            bssid = m.group(1)
            rssi = m.group(2) + " dBm"
            rest = m.group(3).strip()
            sec = rest.split()[-1] if rest else ""
            ssid = line.split(bssid)[0].strip()
            networks.append({"ssid": ssid, "bssid": bssid, "signal": rssi, "auth": sec})
    return networks

def parse_iwlist(output):
    networks = []
    cells = output.split("Cell ")
    for c in cells[1:]:
        ssid = ""; bssid = ""; signal = ""; auth = ""
        m = re.search(r"Address: ([0-9A-Fa-f:]{17})", c)
        if m: bssid = m.group(1)
        m = re.search(r'ESSID:"([^"]*)"', c)
        if m: ssid = m.group(1)
        m = re.search(r"Signal level[=\:]-?(\d+)", c)
        if m: signal = m.group(1) + " dBm"
        if "Encryption key:off" in c:
            auth = "Open"
        else:
            if "WPA2" in c or "wpa2" in c:
                auth = "WPA2"
            elif "WPA" in c or "wpa" in c:
                auth = "WPA"
            else:
                auth = "Encrypted"
        networks.append({"ssid": ssid, "bssid": bssid, "signal": signal, "auth": auth})
    return networks

#####################
# Scanning function #
#####################

def scan_networks():
    osname = platform.system().lower()
    print(COLOR_WHITE + f"Detected OS: {platform.system()}")
    if osname.startswith("windows"):
        print(COLOR_YELLOW + "Using netsh wlan show networks (mode=bssid)")
        out = run_cmd("netsh wlan show networks mode=bssid")
        return parse_netsh(out)
    elif osname.startswith("linux"):
        if shutil.which("nmcli"):
            print(COLOR_YELLOW + "Using nmcli to list Wi-Fi networks.")
            out = run_cmd("nmcli -f SSID,SIGNAL,SECURITY,BSSID -t device wifi list")
            return parse_nmcli(out)
        elif shutil.which("iwlist"):
            print(COLOR_YELLOW + "Using iwlist scan (may require sudo).")
            out = run_cmd("iwlist scan")
            return parse_iwlist(out)
        else:
            print(Fore.RED + "No nmcli or iwlist found. Install NetworkManager (nmcli) or wireless-tools (iwlist).")
            return []
    elif osname.startswith("darwin"):
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if shutil.which(airport_path) or shutil.which("airport"):
            cmd = (airport_path + " -s") if shutil.which(airport_path) else "airport -s"
            print(COLOR_YELLOW + "Using airport -s (macOS).")
            out = run_cmd(cmd)
            return parse_airport(out)
        else:
            print(Fore.RED + "airport utility not found on macOS.")
            return []
    else:
        print(Fore.RED + "Unsupported OS.")
        return []

############################
# UI + simulated attack
############################

def header():
    # Banner + the requested bold-green notice
    print(Fore.RED + Style.BRIGHT + RED_BANNER)
    print(COLOR_GREEN + Style.BRIGHT + "Md Rahil Sheikh Raj. Use For Only Entertaintment Purpose. Use wlan0 for Good Experience.")
    # small separator/footer
    print(Style.DIM + Fore.WHITE + "Other options remain below.")
    print()

def pretty_print_networks(nets):
    if not nets:
        print(Fore.RED + "No networks found or scanner failed.")
        return
    print(Fore.GREEN + f"Found {len(nets)} networks:")
    for i, n in enumerate(nets, 1):
        ssid = n.get("ssid") or "<Hidden>"
        bssid = n.get("bssid") or ""
        sig = n.get("signal") or ""
        auth = n.get("auth") or ""
        print(f" {Fore.CYAN}[{i}] {Fore.WHITE}{ssid:30} {Fore.MAGENTA}{auth:12} {Fore.YELLOW}{sig:8} {Fore.LIGHTBLACK_EX}{bssid}")

def choose_network_and_fake_attack(nets):
    if not nets:
        input(COLOR_GREEN + "Press Enter to return to menu...")
        return
    while True:
        choice = input(COLOR_GREEN + "Select a network number to target (or B to go back): ").strip()
        if choice.lower() == "b":
            return
        if not choice.isdigit():
            print(Fore.RED + "Enter a number or B.")
            continue
        idx = int(choice) - 1
        if idx < 0 or idx >= len(nets):
            print(Fore.RED + "Invalid index.")
            continue
        target = nets[idx]
        print(COLOR_WHITE + f"Selected: {target.get('ssid') or '<Hidden>'}  {target.get('bssid')}")
        fake_clients = ["Rahil", "Mizan", "GuestPhone", "Laptop-123", "Camera-01"]
        random.shuffle(fake_clients)
        displayed = fake_clients[: random.randint(1, len(fake_clients))]
        print(COLOR_YELLOW + "Discovered clients (simulated):")
        for i, c in enumerate(displayed, 1):
            print(COLOR_GREEN + f" [{i}] {c}")
        pick = input(COLOR_GREEN + "Choose client number to 'attack' (simulated) or B: ").strip()
        if pick.lower() == "b":
            return
        if not pick.isdigit():
            print(Fore.RED + "Invalid input.")
            return
        p = int(pick) - 1
        if p < 0 or p >= len(displayed):
            print(Fore.RED + "Invalid client.")
            return
        client = displayed[p]
        # Simulated attack sequence
        print()
        print(COLOR_ORANGE + "Preparing exploit framework (simulated)...")
        time.sleep(0.6)
        steps = ["Enumerating services", "Injecting fake payload", "Elevating simulation privileges", "Brute-forcing (simulated)"]
        for step in steps:
            print(COLOR_PINK + step + "...")
            time.sleep(0.8 + random.random()*0.6)
        # fake progress
        prog = "#" * random.randint(8, 24)
        print(COLOR_GREEN + "Progress: [" + prog + " ]")
        time.sleep(0.6)
        print(Fore.RED + Style.BRIGHT + "\nAttack Performed — Password Destroyed")
        print(Fore.MAGENTA + "(This was only a simulation. No real device was accessed or harmed.)")
        print()
        input(COLOR_GREEN + "Press Enter to return to scan results...")
        return

def show_device_info():
    import platform as _pl
    print(COLOR_GREEN + "Device Model: " + Fore.CYAN + _pl.machine())
    print(COLOR_GREEN + "System: " + Fore.CYAN + _pl.system() + " " + _pl.release())
    print(COLOR_GREEN + "Python: " + Fore.CYAN + _pl.python_version())
    ram = random.choice([4,8,12,16,32])
    print(COLOR_GREEN + "RAM: " + Fore.CYAN + f"{ram} GB")
    cpu = _pl.processor() or "Unknown CPU"
    print(COLOR_GREEN + "CPU: " + Fore.CYAN + cpu)
    print()
    input(COLOR_GREEN + "Press Enter to return to menu...")

def hotspot_publish_simulated():
    name = input(COLOR_YELLOW + "Enter Your Publishing Hotspot Name : ").strip() or "Simulated_Hotspot"
    port = input(COLOR_GREEN + "Enter A Port (e.g. 8080): ").strip()
    if not port.isdigit():
        print(Fore.RED + "Invalid port. Using 8080.")
        port = "8080"
    print()
    print(COLOR_YELLOW + f"Creating hotspot '{name}' on port {port} (simulated)...")
    for i in range(3):
        print(COLOR_GREEN + "Activating" + "." * (i+1))
        time.sleep(0.5)
    print(COLOR_PINK + Style.BRIGHT + f"Hotspot '{name}' is now ACTIVE (SIMULATED).")
    print(Fore.CYAN + "Note: This is a local simulation. It does NOT change your system's network settings.")
    input(COLOR_GREEN + "Press Enter to return to menu...")

def confirm_usage():
    print(Fore.RED + "WARNING: Only scan networks you own or have explicit permission to scan.")
    ok = input(Fore.YELLOW + "Type YES to confirm you have permission and continue: ").strip()
    if ok != "YES":
        print(COLOR_WHITE + "Confirmation not given. Exiting.")
        sys.exit(0)

def main():
    confirm_usage()
    while True:
        header()
        # main menu (keeps numeric choices; the earlier color-word menu is removed)
        print(COLOR_YELLOW + "[1] Scan real Wi-Fi networks")
        print(COLOR_PINK + "[2] Device Infos")
        print(COLOR_ORANGE + "[3] Hotspot Publish (simulated)")
        print(COLOR_WHITE + "[X] Exit")
        choice = input(COLOR_GREEN + "Choice: ").strip().lower()
        if choice == "1":
            nets = scan_networks()
            pretty_print_networks(nets)
            choose_network_and_fake_attack(nets)
        elif choice == "2":
            show_device_info()
        elif choice == "3":
            hotspot_publish_simulated()
        elif choice == "x":
            print(COLOR_WHITE + "Exiting. Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "Invalid choice. Try 1,2,3 or X.")
            time.sleep(0.6)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + COLOR_WHITE + "Interrupted. Exiting.")
