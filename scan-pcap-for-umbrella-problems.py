#!/usr/bin/env python

"""
Cisco Umbrella PCAP Diagnostic Tool
===================================

Description:
This tool is designed to analyze PCAP or PCAPNG files generated from a Cisco Umbrella client machine. 
It identifies DNS queries to specific monitored domains and detects TCP SYN packets that do not receive 
a corresponding SYN/ACK response, which may indicate that these packets are being blocked by an enterprise firewall.

Features:
- Extracts DNS queries to monitored domains and their responses.
- Identifies unestablished TCP sessions (SYN packets without ACK) to monitored ports (default: 80, 443).
- Displays blocked packets along with the associated domain name (if resolvable).
- Supports output in text or JSON format for easy integration with other tools.

Usage Instructions:
1. Before starting the packet capture:
   - Stop all Cisco services on the client machine.
   - Start the packet capture using a tool like Wireshark or tcpdump.
   - Run the command: `ipconfig /flushdns` to clear the DNS cache.
   - Start the Cisco AnyConnect VPN service.
2. Let the capture run for approximately 1 minute.
3. Stop the packet capture and save the file in PCAP or PCAPNG format.
4. Use this tool to analyze the generated file:
   ```
   python scan-pcap-for-umbrella-problems.py <path_to_pcap_file>
   ```

Command-line Options:
- `--domains`: Specify a custom list of monitored domains (default: predefined Cisco and Okta domains).
- `--ports`: Specify a custom list of monitored ports (default: 80, 443).
- `-o` or `--output`: Choose the output format (`text` or `json`, default: `text`).
- `-b` or `--no-banner`: Suppress the banner display.

Example:
```
python scan-pcap-for-umbrella-problems.py capture.pcap --output json
```

Note:
Ensure that the PCAP file contains traffic generated during the specified capture process for accurate results.
"""

import argparse
import json  # Add import for JSON handling
from scapy.all import rdpcap, DNSQR, IP, TCP, Scapy_Exception

# Configuration: List of monitored domains and ports
MONITORED_DOMAINS = [
    'isrg.trustid.ocsp.identrust.com',
    '.cisco.com',
    '.opendns.com',
    '.umbrella.com',
    'www.msftconnecttest.com',
    'connecttest.cisco.io',
    '*.okta.com',
    '*.oktacdn.com',
    '*.pingidentity.com',
    'secure.aadcdn.microsoftonline-p.com'
]
MONITORED_PORTS = [80, 443]

def print_banner():
    """Displays a banner for the tool."""
    print("=" * 50)
    print("          Cisco Umbrella PCAP Diagnostic Tool")
    print("          DNS and TCP SYN/ACK Analysis")
    print("=" * 50)

def extract_dns_queries(packets):
    """Extracts DNS queries and associated responses for monitored domains."""
    dns_queries = {}
    for pkt in packets:
        try:
            if pkt.haslayer(DNSQR):  # DNS Query
                query_name = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                if any(query_name.endswith(domain) for domain in MONITORED_DOMAINS):
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else 'Unknown'
                    if query_name not in dns_queries:
                        dns_queries[query_name] = {"sources": set(), "responses": set()}
                    dns_queries[query_name]["sources"].add(src_ip)
            if pkt.haslayer("DNSRR"):  # DNS Response
                query_name = pkt["DNS"].qd.qname.decode('utf-8').rstrip('.')
                if any(query_name.endswith(domain) for domain in MONITORED_DOMAINS):
                    for i in range(pkt["DNS"].ancount):
                        rr = pkt["DNS"].an[i]
                        if rr.type == 1 and hasattr(rr, "rdata"):  # A record (IPv4) with valid rdata
                            ip_address = str(rr.rdata)
                            if query_name not in dns_queries:
                                dns_queries[query_name] = {"sources": set(), "responses": set()}
                            dns_queries[query_name]["responses"].add(ip_address)
        except (AttributeError, UnicodeDecodeError, IndexError):
            # Ignore malformed or undecodable packets
            continue
    return dns_queries

def extract_syn_packets(packets):
    """Extracts SYN packets without ACK."""
    syn_packets = {}
    for pkt in packets:
        try:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):  # Check for TCP and IP layers
                tcp_layer = pkt[TCP]
                if tcp_layer.flags == 'S':  # SYN Packet
                    key = (pkt[IP].src, pkt[IP].dst, tcp_layer.dport)
                    syn_packets[key] = True
                elif tcp_layer.flags == 'A':  # ACK Packet
                    key = (pkt[IP].dst, pkt[IP].src, tcp_layer.sport)
                    if key in syn_packets:
                        syn_packets[key] = False  # Mark as having received an ACK
        except AttributeError:
            # Ignore malformed packets
            continue
    return [(src, dst, port) for (src, dst, port), is_syn_without_ack in syn_packets.items() if is_syn_without_ack]

def display_statistics(dns_queries, ip_ports, output_format="text"):
    """Displays statistics for DNS queries and TCP packets."""
    if output_format == "json":
        result = {
            "dns_queries": {domain: list(data["responses"]) for domain, data in dns_queries.items()},
            "tcp_packets": [{"src": src, "dst": dst, "port": port} for src, dst, port in ip_ports],
        }
        print(json.dumps(result, indent=2))
    else:
        print("\n[+] DNS Queries to monitored domains:")
        for domain, data in dns_queries.items():
            responses = ', '.join(data["responses"])
            print(f"  {domain}: {responses}")

        print("\n[+] TCP Packets to ports 80 or 443 (SYN received, but no related SYN/ACK found):")
        for src, dst, port in ip_ports:
            warning = ""
            for domain, data in dns_queries.items():
                if dst in data["responses"]:
                    warning = f"      \u001b[33m\u26A0 {domain}\u001b[0m"
                    break
            print(f"  {src} -> {dst}:{port}{warning}")

def parse_pcap(file_path):
    """Analyzes the PCAP file and returns statistics."""
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return {}, []
    except Scapy_Exception as e:
        print(f"Error reading the PCAP file: {e}")
        return {}, []

    dns_queries = extract_dns_queries(packets)
    ip_ports = extract_syn_packets(packets)
    return dns_queries, ip_ports

def display_parameters(pcap_file, output_format):
    """Displays the monitored parameters."""
    print("-" * 50)
    print("  Output format  : ", output_format)
    print("  PCAP file path : ", pcap_file)
    print("-" * 50)
    print("  Monitored domains:")
    for domain in MONITORED_DOMAINS:
        print(f"    - {domain}")
    print("  Monitored ports:")
    for port in MONITORED_PORTS:
        print(f"    - {port}")
    print("-" * 50)

def main():
    global MONITORED_DOMAINS, MONITORED_PORTS
    """Main entry point of the tool."""
    # Assign global variables to local variables for argparse defaults
    default_domains = MONITORED_DOMAINS
    default_ports = MONITORED_PORTS

    # Command-line argument handling
    parser = argparse.ArgumentParser(
        description="""Cisco Umbrella PCAP Diagnostic Tool
        This tool analyzes PCAP files for DNS queries and TCP SYN/ACK packets related to Cisco Umbrella and Okta services.
        It identifies DNS queries to domains defined in Umbrella clients prerequisites and also list unestablished TCP sessions to port 80 and 443
        to help identifying potential missing Firewall rules that may block the client from working properly.""",
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP file to analyze",
    )
    parser.add_argument(
        "--domains",
        nargs="*",
        default=default_domains,
        help="List of monitored domains (default: .cisco.com, .okta.com)",
    )
    parser.add_argument(
        "--ports",
        nargs="*",
        type=int,
        default=default_ports,
        help="List of monitored ports (default: 80, 443)",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-b", "--no-banner",
        action="store_true",
        help="Suppress the banner display",
    )
    args = parser.parse_args()

    # Update monitored domains and ports
    MONITORED_DOMAINS = args.domains
    MONITORED_PORTS = args.ports

    # Handle banner and summary display based on options
    if args.output != "json" and not args.no_banner:
        print_banner()
        display_parameters(args.pcap_file, args.output)

    # Analyze the PCAP file
    dns_queries, ip_ports = parse_pcap(args.pcap_file)

    # Display statistics in the specified output format
    display_statistics(dns_queries, ip_ports, output_format=args.output)

if __name__ == "__main__":
    main()
