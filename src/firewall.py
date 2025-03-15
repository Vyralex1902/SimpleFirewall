# src/firewall.py
from scapy.all import sniff, IP
import json
import os


# Load firewall rules from configuration file
def load_rules(config_path="config/firewall_rules.json"):
    if not os.path.exists(config_path):
        # Default rule: block no IP addresses
        return {"blocked_ips": []}
    with open(config_path, "r") as f:
        return json.load(f)


# Evaluate a packet against the rules
def evaluate_packet(packet, rules):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        if src_ip in rules.get("blocked_ips", []):
            print(
                f"[BLOCKED] Packet from {src_ip} dropped"
            )  # I might add colored messages in the future
        else:
            print(
                f"[ALLOWED] Packet from {src_ip} accepted"
            )  # I might add colored messages in the future


# Callback for each captured packet
def packet_callback(packet):
    rules = load_rules()  # Load or refresh rules
    evaluate_packet(packet, rules)


def start_firewall():
    print("Starting firewall...")
    # Note: Running this script requires administrative privileges
    sniff(filter="ip", prn=packet_callback)


if __name__ == "__main__":
    start_firewall()
