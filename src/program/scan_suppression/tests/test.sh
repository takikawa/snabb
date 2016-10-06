#!/usr/bin/env bash

sudo ../../../snabb scan_suppression check "192.168.100.102" simple-nmap.pcap /tmp/simple-nmap-out.pcap
cmp simple-nmap-out.pcap /tmp/simple-nmap-out.pcap
sudo ../../../snabb scan_suppression check "192.168.100.102" hygiene-check.pcap /tmp/hygiene-check-out.pcap
cmp hygiene-check-out.pcap /tmp/hygiene-check-out.pcap
