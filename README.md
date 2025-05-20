# PCAP TCP SYN/ACK Analyzer

A tool for analyzing PCAP files to detect potential SYN flood attacks by measuring the percentage of SYN packets that receive ACK responses.

## Overview

This Python script analyzes network packet capture (PCAP) files to determine the percentage of TCP SYN packets that were acknowledged with ACK packets. It's particularly useful for:

- Identifying potential SYN flood attacks
- Analyzing network connection success rates
- Understanding server response behavior
- Network troubleshooting

The tool parses PCAP files directly without requiring external packet analysis libraries, making it lightweight and easy to deploy.

## Features

- Direct PCAP file parsing without external dependencies
- Counts incoming SYN packets to port 80
- Counts outgoing ACK packets from port 80
- Calculates the percentage of SYNs that received ACKs
- Detects potential SYN flood attacks
- Handles malformed packets gracefully

# Goal

- Made this project to get some practice and understand binary encodings of data.
- Wanted to learn how to capture and analyze packets

## Acknowledgments

- This tool was created for educational and network diagnostic purposes
- It uses direct PCAP parsing techniques to avoid external dependencies
- This project is based on an exercise provided by csprimer.com
- It was developed as part of the Computer Systems Primer curriculum
