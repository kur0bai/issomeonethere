import argparse
import subprocess
import datetime
import sys
import threading
import time
from colorama import Fore, Style
import shutil
import re
import os

LOG_FILE = "meterpreter_detection.log"


class Spinner:
    """
    Function to show and hide spinner animation
    """

    def __init__(self, message="Loading"):
        self.spinner = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.message = message
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

        # clean
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()

    def _animate(self):
        while self.running:
            for frame in self.spinner:
                if not self.running:
                    break
                sys.stdout.write(f"\r{self.message} {frame} ")
                sys.stdout.flush()
                time.sleep(0.1)  # speed


def show_banner():
    """
    Main identifier banner
    """
    banner = [
        (Fore.GREEN +
         r" __          ___           _  _______ _                   "),
        (Fore.GREEN +
         r" \ \        / / |         (_)|__   __| |"),
        (Fore.GREEN +
         r"  \ \  /\  / /| |__   ___  _ ___| |  | |__   ___ _ __ ___"),
        (Fore.GREEN +
         r"   \ \/  \/ / | '_ \ / _ \| / __| |  | '_ \ / _ \ '__/ _ \\"),
        (Fore.GREEN +
         r"    \  /\  /  | | | | (_) | \__ \ |  | | | |  __/ | |  __/"),
        (Fore.GREEN +
         r"     \/  \/   |_| |_|\___/|_|___/_|  |_| |_|\___|_|  \___|"),
        (Fore.CYAN + r""),
        (Fore.CYAN +
         r"        -------------- By: Kur0bai ------------------"),
        Style.RESET_ALL
    ]

    for line in banner:
        print(line)


"""
    This script is designed to detect suspicious activity on a system,
    particularly looking for meterpreter shells and
    other network-related anomalies.
    It provides functionalities to scan local devices,
    check for active processes,inspect network connections,
    and manage firewall rules.
    The script requires root privileges to run certain commands
    and uses color-coded output for better readability.
"""


def ensure_root():
    if os.geteuid() != 0:
        print(Fore.RED +
              "❌ This script must be run as root. Try: sudo python3 script.py"
              )
        sys.exit(1)


def check_command_exists(command: str):
    if shutil.which(command) is None:
        print(Fore.RED +
              f"❌ Required command `{command}` not found in system PATH."
              )
        sys.exit(1)


def validate_interface(interface: str):
    if not re.match(r"^[a-zA-Z0-9_.-]+$", interface):
        print(Fore.RED + "❌ Invalid network interface name.")
        sys.exit(1)


def validate_port(port: str):
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        print(Fore.RED + "❌ Invalid port number.")
        sys.exit(1)


def validate_pid(pid: str):
    if not pid.isdigit():
        print(Fore.RED + f"❌ Invalid PID: {pid}")
        return False
    return True


def log_detection(content: str):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {content}\n")


def run_detect_local_devices(interface: str):
    command = ["arp-scan", f"--interface={interface}", "--localnet"]
    try:
        result = subprocess.run(command,
                                check=True, text=True, capture_output=True)
        # nosec B603
        print(Fore.GREEN + r"Local devices connected: ")
        print(Fore.WHITE + f"{result.stdout}")
    except Exception as ex:
        raise ex


def run_detect_meterpreter_shells():
    try:
        spinner = Spinner(
            "Checking for meterpreter shells in your machine")
        spinner.start()
        command = ["pgrep", "-af", "meterpreter"]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )  # nosec B603
        lines = [line for line in result.stdout.splitlines()
                 if 'meterpreter' in line.lower()]
        if lines:
            spinner.stop()
            print(
                Fore.RED +
                r"⚠️ Alert! suspicious processes with 'meterpreter': \n"
                )
            for line in lines:
                print(line)
                log_detection("Detected processes:")
            for line in lines:
                log_detection(line)
            return lines
        else:
            spinner.stop()
            print(Fore.CYAN +
                  r"✅ Active processes running meterpreter not found."
                  )
            return False

    except FileNotFoundError:
        print(Fore.RED +
              r"Ups `pgrep` command are not available in this system."
              )
        return False


def run_netstat():
    spinner = Spinner(
        Fore.GREEN + r"Running netstat to get active connections ")
    spinner.start()
    command = ["netstat", "-tunp"]
    try:
        result = subprocess.run(command,
                                check=True, text=True, capture_output=True)
        # nosec B603
        print('\n')
        print(Fore.WHITE + f"{result.stdout}")
        spinner.stop()
    except Exception as ex:
        spinner.stop()
        raise ex


def run_open_files(port: str):
    if not port.isdigit():
        print("⚠️ Invalid port number.")
        return

    if shutil.which("lsof") is None:
        print("❌ `lsof` command not found. Please install it.")
        return

    command = ["lsof", "-i", f":{port}"]
    try:
        result = subprocess.run(command, check=True, text=True,
                                capture_output=True)  # nosec B603
        print('\n')
        if result.returncode == 0:
            print(Fore.WHITE + result.stdout)
        elif result.returncode == 1:
            print(Fore.CYAN + f"ℹ️ No processes found using port {port}.")
        else:
            print(Fore.RED +
                  f"❌ Unexpected error running lsof.{result.returncode}")
            print(result.stderr)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error running lsof: {e}")


def run_block_port_on_firewall(port: str):
    command = ["ufw", "deny", f"{port}"]
    try:
        if port.isdigit():
            result = subprocess.run(command,
                                    check=True, text=True, capture_output=True)
            # nosec B603
            print('\n')
            print(Fore.WHITE + f"{result.stdout}")
        else:
            print("⚠️ Invalid port number.")
    except Exception as ex:
        raise ex


def extract_pids(process_lines):
    pids = []
    for line in process_lines:
        parts = line.split()
        if len(parts) > 1:
            pid = parts[1]
            if pid.isdigit():
                pids.append(pid)
    return pids


def kill_processes(pids):
    print('\n')
    for pid in pids:
        try:
            command = ["kill", "-9", pid]
            subprocess.run(command, check=True)  # nosec B603
            print(Fore.CYAN + f"✅ Process {pid} killed.")
            log_detection(f"Process {pid} killed.")
        except subprocess.CalledProcessError:
            print(Fore.RED + f"❌ Error killing the process {pid}.")
            log_detection(f"Error killing the process {pid}.")


def get_args():
    parser = argparse.ArgumentParser(description="Detect someone in your pc")
    parser.add_argument("--interface", type=str,
                        required=True,
                        help="Internet interface name, use 'ifconfig'")
    args = parser.parse_args()
    return args


def prompt_yes_no(message: str) -> bool:
    response = input(f"{message} (y/n): ").strip().lower()
    return response == 'y'


def prompt_for_pids() -> list:
    pids_input = input(
        f'Please enter the PIDs separated by space: {Fore.CYAN}')
    return pids_input.strip().split()


def prompt_for_port() -> str:
    return input(f'Please enter the port number: {Fore.CYAN}').strip()


def main():
    ensure_root()
    args = get_args()

    validate_interface(args.interface)
    check_command_exists("arp-scan")
    run_detect_local_devices(args.interface)

    check_command_exists("pgrep")
    processes = run_detect_meterpreter_shells()

    if processes:
        pids = extract_pids(processes)
        if prompt_yes_no("Do you want to kill these processes?"):
            spinner = Spinner(Fore.GREEN + r"🗡️ Killing processes ")
            spinner.start()
            kill_processes(pids)
            spinner.stop()

    check_command_exists("netstat")
    run_netstat()

    if prompt_yes_no("Do you want to inspect a specific port?"):
        port = prompt_for_port()
        validate_port(port)
        check_command_exists("lsof")

        spinner = Spinner(Fore.GREEN + r"Checking this port, please wait ")
        spinner.start()
        run_open_files(port)
        spinner.stop()

        if prompt_yes_no("Do you want to kill specific processes?"):
            pids = prompt_for_pids()
            pids = [pid for pid in pids if validate_pid(pid)]

            spinner = Spinner(Fore.CYAN + r"🗡️ Killing processes ")
            spinner.start()
            kill_processes(pids)
            spinner.stop()

            run_open_files(port)

            if prompt_yes_no("Do you want to block this port?"):
                check_command_exists("ufw")
                run_block_port_on_firewall(port)

    print(Fore.GREEN + r"👋 See you next time!")


if __name__ == "__main__":
    show_banner()
    main()
