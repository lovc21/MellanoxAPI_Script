# Mellanox simple API Script for Openflow

## About

This Python script is a simple CLI that captures user input through Python console/CLI. It issues OpenFlow commands to
the Mellanox switch using its API on your behalf, so you don't need to know the exact syntax of the commands.

The script issues OpenFlow commands for IPv4 and IPv6 or custom commands.

## Running the script

> python3 MellanoxScript.py

## Usage

When prompted by the program, input your choice to the console:

1. Adding IPv4 OpenFlow rule(s)
2. Adding IPv6 OpenFlow rule(s)
3. Adding a custom OpenFlow rule(s)
4. Deleting specific rule(s)
5. Deleting all rules
6. Show current OpenFlow rules
7. Import rules from a text file ; [see the instructions below](text-file-input).
8. Issue a custom CLI command

### Text file input

When trying to import multiple rules from file, the file should be formatted as:

```
priority=<priority>|in_port=Eth1/<port>|actions=push_vlan:0x8100,set_field:6395->vlan_vid,output:52,output:54
priority=<priority>|in_port=Eth1/<port>|nw_src=1.1.1.1|actions=output:1,output:10
priority=<priority>|in_port=Eth1/<port>|ipv6_src=2001:2000::|actions=output:1,output:10

```

or more generally

```
|attribute=value|...|actions=set_field:6395->vlan_vid,output:52,output:54
```

