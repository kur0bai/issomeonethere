import argparse
import subprocess
from typing import List


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
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            print("⚠️  Warning! There are active process running meterpreter:")
            print(result.stdout.strip())
            return True
        else:
            print("✅ Active process running meterpreter not found.")
            return False
    except FileNotFoundError:
        print("Ups `pgrep` command are not available in this system.")
        return False


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
        "Check for actives reverse meterpreter shells? y/n: ")
    if (get_meterpreter == "y"):
        run_detect_meterpreter_shells()


if __name__ == "__main__":
    main()
