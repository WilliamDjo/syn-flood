#!/usr/bin/env python3
"""
TCP SYN/ACK Packet Analyzer

This script analyzes a PCAP file to determine the percentage of incoming SYN messages
that were ACKed. It parses the PCAP file format directly without using external libraries,
counts SYN packets sent to port 80 and ACK packets sent from port 80, then calculates
the percentage of SYN packets that received an ACK response.

Usage:
    python syn_ack_analyzer.py

The script expects a file named "synflood.pcap" in the same directory.
"""

import struct
from typing import Dict, Tuple, BinaryIO

# TCP Flag constants
TCP_SYN = 0x0002
TCP_ACK = 0x0010

# Ethernet + IP header constants
IPV4_ETHERTYPE = 2
HTTP_PORT = 80


def read_pcap_global_header(file: BinaryIO) -> Dict:
    """
    Parse the global header of a PCAP file.

    Args:
        file: An open binary file object positioned at the start of the PCAP file.

    Returns:
        A dictionary containing the parsed global header fields.

    Raises:
        AssertionError: If the magic number doesn't match the expected PCAP format.
    """
    global_header_data = file.read(24)
    magic_number = struct.unpack("I", global_header_data[0:4])[0]

    # Validate that this is a valid PCAP file
    assert magic_number == 0xA1B2C3D4, "Invalid PCAP file: incorrect magic number"

    # Unpack the global header fields
    fmt = "<IHHIIII"
    fields = struct.unpack(fmt, global_header_data)

    return {
        "magic_number": hex(fields[0]),
        "version_major": fields[1],
        "version_minor": fields[2],
        "timezone_offset": fields[3],
        "timestamp_accuracy": fields[4],
        "snaplen": fields[5],
        "link_layer_type": fields[6],
    }


def read_packet_header(file: BinaryIO) -> Dict:
    """
    Read and parse a packet header from a PCAP file.

    Args:
        file: An open binary file object positioned at the start of a packet header.

    Returns:
        A dictionary containing the parsed packet header fields,
        or None if the end of file is reached.
    """
    packet_header_data = file.read(16)

    # Check if we've reached the end of the file
    if len(packet_header_data) < 16:
        return None

    ph = struct.unpack("<IIII", packet_header_data)

    return {
        "timestamp_sec": ph[0],
        "timestamp_microsec": ph[1],
        "caplen": ph[2],
        "orglen": ph[3],
    }


def parse_tcp_packet(packet_data: bytes) -> Tuple[Dict, bool]:
    """
    Parse a TCP packet and extract relevant information.

    Args:
        packet_data: Binary packet data from the PCAP file.

    Returns:
        A tuple containing:
        - A dictionary with TCP header information
        - A boolean indicating if the packet is IPv4 (True) or not (False)

    Raises:
        AssertionError: If the packet is not IPv4.
    """
    # Check if it's an IPv4 packet by extracting EtherType
    ethertype = struct.unpack("<I", packet_data[:4])[0]
    if ethertype != IPV4_ETHERTYPE:
        return None, False

    # Calculate IP header length to find where TCP header starts
    ihl = (packet_data[4] & 0x0F) << 2

    # Parse TCP header (starts after IP header)
    tcp_header_data = packet_data[24:38]
    tcp_fields = struct.unpack("!HHIIH", tcp_header_data)

    tcp_header = {
        "src_port": tcp_fields[0],
        "dst_port": tcp_fields[1],
        "seq_num": tcp_fields[2],
        "ack_num": tcp_fields[3],
        "flags": tcp_fields[4],
    }

    return tcp_header, True


def is_syn_packet(tcp_header: Dict) -> bool:
    """Check if a TCP packet has the SYN flag set."""
    return (tcp_header["flags"] & TCP_SYN) > 0


def is_ack_packet(tcp_header: Dict) -> bool:
    """Check if a TCP packet has the ACK flag set."""
    return (tcp_header["flags"] & TCP_ACK) > 0


def analyze_pcap_file(filename: str) -> Tuple[int, int, float]:
    """
    Analyze a PCAP file to count SYN and ACK packets on port 80.

    Args:
        filename: Path to the PCAP file to analyze.

    Returns:
        A tuple containing:
        - Number of SYN packets to port 80 (initiated connections)
        - Number of ACK packets from port 80 (acknowledged connections)
        - Percentage of SYN packets that were ACKed
    """
    initiated = 0  # Count of SYN packets to port 80
    acked = 0  # Count of ACK packets from port 80

    with open(filename, "rb") as f:
        # Parse global header
        header = read_pcap_global_header(f)
        print(f"PCAP Version: {header['version_major']}.{header['version_minor']}")

        # Process each packet
        while True:
            # Read packet header
            p_header = read_packet_header(f)
            if p_header is None:
                break  # End of file reached

            # Read packet data
            packet_data = f.read(p_header["caplen"])

            try:
                # Parse TCP packet
                tcp_header, is_ipv4 = parse_tcp_packet(packet_data)

                if not is_ipv4:
                    continue  # Skip non-IPv4 packets

                # Count incoming SYN packets to HTTP port
                if tcp_header["dst_port"] == HTTP_PORT and is_syn_packet(tcp_header):
                    initiated += 1

                # Count outgoing ACK packets from HTTP port
                if tcp_header["src_port"] == HTTP_PORT and is_ack_packet(tcp_header):
                    acked += 1

            except (AssertionError, struct.error, IndexError) as e:
                # Skip malformed packets
                print(f"Warning: Skipping malformed packet: {e}")
                continue

    # Calculate percentage of SYN packets that were ACKed
    ack_percentage = (acked / initiated * 100) if initiated > 0 else 0

    return initiated, acked, ack_percentage


def main():
    """Main function to run the analysis and print results."""
    filename = "synflood.pcap"

    try:
        initiated, acked, ack_percentage = analyze_pcap_file(filename)

        print("\nAnalysis Results:")
        print(f"SYN packets to port {HTTP_PORT}: {initiated}")
        print(f"ACK packets from port {HTTP_PORT}: {acked}")
        print(f"Percentage of SYN packets that were ACKed: {ack_percentage:.2f}%")

        # Detect potential SYN flood attack
        if ack_percentage < 50:
            print("\nWarning: Low ACK percentage may indicate a SYN flood attack!")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")


if __name__ == "__main__":
    main()
