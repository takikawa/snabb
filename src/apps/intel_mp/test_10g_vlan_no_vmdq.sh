#!/usr/bin/env bash
#
# Test vlan tagging without VMDq

./testvlan.snabb $SNABB_PCI_INTEL0 $SNABB_PCI_INTEL1 "90:72:82:78:c9:7a" source-vlan.pcap false
