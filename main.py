import argparse
import subprocess
import datetime

LOG_FILE = "meterpreter_detection.log"


def log_detection(content: str):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {content}\n")


def run_detect_local_devices(interface: str):
    command = f"sudo arp-scan --interface={interface} --localnet"
    try:
        result = subprocess.run(command, shell=True,
                                check=True, text=True, capture_output=True)
        print(f"Local devices connected: {result.stdout}")
    except Exception as ex:
        raise ex


def run_detect_meterpreter_shells():
    try:
        command = ["pgrep", "-af", "meterpreter"]
        # command = ["ps aux | grep meterpreter"]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        lines = [line for line in result.stdout.splitlines()
                 if 'meterpreter' in line.lower()]
        if lines:
            print("⚠️ Warning! suspicious processes running with 'meterpreter': \n")
            for line in lines:
                print(line)
                log_detection("Detected processes:")
            for line in lines:
                log_detection(line)
            return lines
        else:
            print("✅ Active processes running meterpreter not found.")
            return False
    except FileNotFoundError:
        print("Ups `pgrep` command are not available in this system.")
        return False


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
    for pid in pids:
        try:
            command = ["kill", "-9", pid]
            subprocess.run(command, check=True)
            print(f"✅ Process {pid} killed.")
            log_detection(f"Process {pid} killed.")
        except subprocess.CalledProcessError:
            print(f"❌ Error killing the process {pid}.")
            log_detection(f"Error killing the process {pid}.")


def get_args():
    parser = argparse.ArgumentParser(description="Detect someone in your pc")
    parser.add_argument("--interface", type=str,
                        required=True,
                        help="Internet interface name, you can find it typing 'ifconfig'")
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    run_detect_local_devices(args.interface)

    get_meterpreter = input(
        "Check for actives reverse meterpreter shells? y/n: ").strip().lower()
    if (get_meterpreter == "y"):
        processes = run_detect_meterpreter_shells()

        if not processes:
            return

        pids = extract_pids(processes)
        response = input(
            "Do yo want to kill this processes? y/n: ").strip().lower()
        if (response == 'y'):
            kill_processes(pids)


if __name__ == "__main__":
    main()
