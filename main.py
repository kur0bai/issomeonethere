import argparse


def get_args():
    parser = argparse.ArgumentParser(description="Detect someone in your pc")
    parser.add_argument("--interface", type=str,
                        required=True, help="Internet interface name")
    args = parser.parse_args()
