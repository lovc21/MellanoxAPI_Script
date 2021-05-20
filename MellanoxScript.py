#!/usr/bin/python3

import requests
import os

credentials = {"username": "<username>", "password": "<password>"}
session = requests.Session()
url = "http://<ip_address>/admin/launch?script=json"


def login():
    global credentials
    try:
        # login and get session cookie
        r = session.post("http://<ip_address>/admin/launch?script=rh&template=json-request&action=json-login",
                         json=credentials)
        print("---------------------------------------------------------------------\n")
        print("LOGIN")
        print(f"{r.json()}\n")
        print(f"{session.cookies}\n")
        print("Logged in on a Mellanox switch\n")
        print("---------------------------------------------------------------------\n")
    except Exception as ex:
        print("login failed\n")
        exit(-1)


def load_from_file():
    filepath = input("Input path to file to read: ")
    print(filepath)

    if not os.path.isfile(filepath):
        print(f"File path {filepath} does not exist. Exiting...")
        return

    with open(filepath, "r") as fp:
        for line_index, line in enumerate(fp):
            tableID = ""
            vlanID = ""
            new_srcID = ""
            typeID = ""
            new_dstID = ""
            vlan_tci = ""
            nw_port = ""
            ipv6_src = ""
            actionID = ""
            priorityID = ""
            portID = ""
            actions_outputID = ""
            # vlan_id=1337|actions=output:52|
            commands = line.replace(" ", "").split("|")
            # [vlan_id=1337], [actions=output:52]
            for key_value in commands:
                # [vlan_id=1337]
                key_value = key_value.split("=")
                # [vlan_id, 1337]
                print(f"{key_value}")
                for index, _ in enumerate(key_value):
                    if index % 2 == 0:
                        if key_value[index] == "priority":
                            if len(key_value[index + 1]) > 0:
                                priorityID = key_value[index + 1]
                        if key_value[index] == "in_port":
                            if len(key_value[index + 1]) > 0:
                                portID = key_value[index + 1]
                        if key_value[index] == "table_id":
                            if len(key_value[index + 1]) > 0:
                                tableID = key_value[index + 1]
                        if key_value[index] == "vlan_tci":
                            if len(key_value[index + 1]) > 0:
                                vlan_tci = key_value[index + 1]
                        if key_value[index] == "nw_src":
                            if len(key_value[index + 1]) > 0:
                                new_srcID = key_value[index + 1]
                        if key_value[index] == "nw_dst":
                            if len(key_value[index + 1]) > 0:
                                new_dstID = key_value[index + 1]
                        if key_value[index] == "tp_dst":
                            if len(key_value[index + 1]) > 0:
                                nw_port = key_value[index + 1]
                        if key_value[index] == "ipv6_src":
                            if len(key_value[index + 1]) > 0:
                                ipv6_src = key_value[index + 1]
                        if key_value[index] == "actions":
                            if len(key_value[index + 1]) > 0:
                                # actions=set_field:6297->vlan_vid,output:25,output:52,output:54
                                actionID = key_value[index + 1].replace("output:", "output=Eth1/").replace("\n", "")
                                print(actionID)
                    else:
                        continue
            try:
                add_flow(openflowID=str(line_index), priorityID=priorityID, tableID=tableID, portID=portID,
                         new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, vlan_tci=vlan_tci, typeID=typeID,
                         nw_port=nw_port, ipv6_src=ipv6_src, actions_outputID=actions_outputID, actionID=actionID)
            except Exception as ex:
                print(ex)
                break


def add_flow(openflowID, tableID, priorityID, portID, new_srcID, new_dstID, vlanID, vlan_tci, typeID, nw_port, ipv6_src,
             actions_outputID, actionID):
    command = "openflow add-flows "
    if len(openflowID) > 0:
        command = f"{command}{openflowID}"
    if len(tableID) > 0:
        command = f"{command} table={tableID}"
    if len(priorityID) > 0:
        if len(tableID) > 0:
            command = f" {command},priority={priorityID}"
        elif len(tableID) == 0:
            command = f" {command} priority={priorityID}"
    if len(portID) > 0:
        command = f"{command},in_port={portID}"
    if len(new_srcID) > 0:
        command = f"{command},nw_src={new_srcID}"
    if len(new_dstID) > 0:
        command = f"{command},nw_dst={new_dstID}"
    if len(vlanID) > 0:
        command = f"{command},dl_vlan={vlanID}"
    if len(vlan_tci) > 0:
        command = f"{command},vlan_tci={vlan_tci}"
    if len(nw_port) > 0:
        command = f"{command},nw_porto={nw_port}"
    if len(ipv6_src) > 0:
        command = f"{command},ipv6_src={ipv6_src}"
    if len(typeID) > 0:
        command = f"{command},typeID={typeID}"
    if len(actions_outputID) > 0:
        command = f"{command},actions=output={actions_outputID}"
    if len(actionID) > 0:
        command = f"{command},actions={actionID}"
    print(command)
    r = session.post(url, json={"cmd": f"{command}"})
    print("\n", r.json())


def getflows():
    global url
    r = session.post(url, json={"cmd": "show openflow flows"})
    print("---------------------------------------------------------------------\n")
    print("current flows :\n", )
    prettify_json(r.json()["data"], "flow", "value")
    print("---------------------------------------------------------------------\n")


def prettify_json(json: dict, key_prefix: str, value_prefix: str):
    for key, value in json.items():
        print(f"{key_prefix}: {key} \n ")
        print(f"{value_prefix}: {value} \n")


def deleterule():
    global url
    print("Please enter the openflow ID (example ID: openflow add-flows 1-1000)")
    while True:
        try:
            openflowID = input("Enter openflow ID:")
            openflowID = int(openflowID)
            if int(openflowID) > 0:
                print("---------------------------------------------------------------------\n")
                r = session.post(url, json={"cmd": f"openflow del-flows {openflowID}"})
                print("\n", r.json())
        except KeyboardInterrupt:
            print('interrupted!')
            break
        except Exception as ex:
            print(ex)


def deleteallrules():
    global url
    rules = input("Enter yes to delete all rules(y/yes):")
    rules = rules.lower()
    if rules == "y" or rules == "yes":
        r = session.post(url, json={"cmd": "openflow del-flows all"})
        print("\n", r.json())
        print("All flows are deleted")


def newflowfullcustom():
    global url
    while True:
        try:
            print("Enter a full comand in a network switch CLI \n")
            print("Example: openflow add-flows 1000 priority=50,in_port=Eth1/1,actions=output=Eth1/50\n")
            cmd1 = input("Enter command:")
            if len(cmd1) != 0:
                print("---------------------------------------------------------------------\n")
                r = session.post(url, json={"cmd": cmd1})
                print("\n", r.json())
        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv4():
    global url
    tableID = ""
    openflowID = ""
    vlanID = ""
    new_srcID = ""
    typeID = "0x0800"
    new_dstID = ""
    vlan_tci = ""
    nw_port = ""
    ipv6_src = ""
    actionID = ""
    priorityID = ""
    portID = ""
    actions_outputID = ""
    for i in range(15):
        try:
            ### Params
            if i == 1:
                print("IMPORTANT remember the openflow id")
                print("Example: 1-100\n")
                openflowID = input("enter openflow add-flows id: ")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("Example: 1-1000\n")
                priorityID = input("enter a priority : ")
                print("---------------------------------------------------------------------\n")
            elif i == 3:
                print("Example: 1-1000\n")
                print("If empty this rule will not be used")
                tableID = input("enter table 3: ")
                print("---------------------------------------------------------------------\n")
            ###  Match
            elif i == 4:
                print("Example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                portID = input("enter a in_port/entry port:")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("Example nw_src: 10.10.2.2/24 \n")
                print("If empty this rule will not be used")
                new_srcID = input("enter a new_src IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("Example nw_dst: 10.20.1.4/24\n")
                print("If empty this rule will not be used")
                new_dstID = input("Enter a new_dst IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 7:
                print("Example vlan: 16\n")
                print("If empty this rule will not be used")
                vlanID = input("Enter a vlan:")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                print("Example new port: 6\n")
                print("If empty this rule will not be used")
                nw_port = input("Enter a new port: ")
                print("---------------------------------------------------------------------\n")
            elif i == 9:
                print("Example new vlan_tci: 0x1000/0x1000\n")
                print("If empty this rule will not be used")
                vlan_tci = input("Enter a new vlan_tci: ")
                print("---------------------------------------------------------------------\n")
            # Actions and Outputs
            elif i == 12:
                print("Example of a output: Eth1/12, normal, ALL,\n ")
                print("If empty this rule will not be used")
                actions_outputID = input("Enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 13:
                print(
                    "Actions: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("Example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("Enter a action:")
                print("---------------------------------------------------------------------\n")
            elif i == 14:
                try:
                    add_flow(openflowID=openflowID, tableID=tableID, priorityID=priorityID, portID=portID,
                             new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, nw_port=nw_port,
                             vlan_tci=vlan_tci,
                             typeID=typeID, actions_outputID=actions_outputID, ipv6_src=ipv6_src, actionID=actionID)
                except KeyboardInterrupt:
                    print('interrupted!')
                    break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv6():
    global url
    tableID = ""
    openflowID = ""
    vlanID = ""
    new_srcID = ""
    typeID = "0x86DD"
    new_dstID = ""
    vlan_tci = ""
    nw_port = ""
    ipv6_src = ""
    actionID = ""
    priorityID = ""
    portID = ""
    actions_outputID = ""
    for i in range(13):
        try:
            ### Params
            if i == 1:
                print("IMPORTANT remember the openflow id")
                print("example: 1-100\n")
                openflowID = input("enter openflow add-flows id: ")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("example: 1-1000\n")
                priorityID = input("enter a priority : ")
                print("---------------------------------------------------------------------\n")
            elif i == 3:
                print("example: 1-1000\n")
                print("if empty this rule will not be used")
                tableID = input("enter table 3: ")
                print("---------------------------------------------------------------------\n")
            ###  Match
            elif i == 4:
                print("example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                print("if empty this rule will not be used")
                portID = input("enter a in_port/entry port:")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("example nw_src: :00:0c:e9:00:00:01 \n")
                print("if empty this rule will not be used")
                new_srcID = input("enter a new_src IPv6: ")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("example nw_dst: :00:0c:e9:00:00:01\n")
                print("if empty this rule will not be used")
                new_dstID = input("enter a new_dst IPv6: ")
                print("---------------------------------------------------------------------\n")
            elif i == 7:
                print("example vlan: 16\n")
                print("if empty this rule will not be used")
                vlanID = input("enter a vlan:")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                print("example new port: 6\n")
                print("if empty this rule will not be used")
                nw_port = input("enter a new port: ")
                print("---------------------------------------------------------------------\n")
            elif i == 9:
                print("example of a output: Eth1/12, normal, ALL, ")
                print("if empty this rule will not be used")
                actions_outputID = input("enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 11:
                print(
                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("enrer a action:")
                print("---------------------------------------------------------------------\n")
            elif i == 12:
                try:
                    add_flow(openflowID=openflowID, tableID=tableID, priorityID=priorityID, portID=portID,
                             new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, nw_port=nw_port,
                             vlan_tci=vlan_tci, typeID=typeID,
                             actions_outputID=actions_outputID, ipv6_src=ipv6_src, actionID=actionID)
                except KeyboardInterrupt:
                    print('interrupted!')
                    break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def addrule():
    global url
    tableID = ""
    openflowID = ""
    vlanID = ""
    new_srcID = ""
    typeID = "0x86DD"
    new_dstID = ""
    vlan_tci = ""
    nw_port = ""
    ipv6_src = ""
    actionID = ""
    priorityID = ""
    portID = ""
    actions_outputID = ""
    for i in range(15):
        try:
            ### Params
            if i == 1:
                print("IMPORTANT remember the openflow id")
                print("example: 1-100\n")
                openflowID = input("enter openflow add-flows id: ")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("example: 1-1000\n")
                priorityID = input("enter a priority : ")
                print("---------------------------------------------------------------------\n")
            elif i == 3:
                print("example: 1-1000\n")
                print("if empty this rule will not be used")
                tableID = input("enter table 3: ")
                print("---------------------------------------------------------------------\n")
            ###  Match stvari
            elif i == 4:
                print("example EtherType: 0x0800 == IPv4, 0x0806 == ARP, 0x86DD ==IPv6")
                print("if left empty type will be IPv4")
                typeID = input("enter a packet type: ")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                print("if empty this rule will not be used")
                portID = input("enter a in_port/entry port:")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("example nw_src: \n")
                print("if empty this rule will not be used")
                new_srcID = input("enter a new_src IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 7:
                print("Example nw_dst: \n")
                print("If empty this rule will not be used")
                new_dstID = input("Enter a new_dst IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                print("Example vlan: 16\n")
                print("If empty this rule will not be used")
                vlanID = input("Enter a vlan:")
                print("---------------------------------------------------------------------\n")
            elif i == 9:
                print("Example new port: 6\n")
                print("If empty this rule will not be used")
                nw_port = input("Enter a new port: ")
                print("---------------------------------------------------------------------\n")
            elif i == 10:
                print("Example new vlan_tci: 0x1000/0x1000\n")
                print("If empty this rule will not be used")
                vlan_tci = input("Enter a new vlan_tci: ")
                print("---------------------------------------------------------------------\n")
            elif i == 11:
                print("Example new ipv6_src: 2001:2000::\n")
                print("If empty this rule will not be used")
                ipv6_src = input("Enter a new ipv6_src: ")
                print("---------------------------------------------------------------------\n")
            ### Actions and Output
            elif i == 12:
                print("example of a output: Eth1/12, normal, ALL, ")
                print("if empty this rule will not be used")
                actions_outputID = input("Enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 13:
                print(
                    "Actions: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("Example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("Enter a action:")
                print("---------------------------------------------------------------------\n")
            elif i == 14:
                try:

                    add_flow(openflowID=openflowID, tableID=tableID, priorityID=priorityID, portID=portID,
                             new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, vlan_tci=vlan_tci,
                             typeID=typeID, nw_port=nw_port, ipv6_src=ipv6_src, actions_outputID=actions_outputID,
                             actionID=actionID)

                except KeyboardInterrupt:
                    print('interrupted!')
                    break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def ChooseAnAction():
    print('''Choose an action\n
                                        1 - Add simple IPv4 Rule  
                                        2 - Add simple IPv6 Rule 
                                        3 - Add custom Rule
                                        4 - Delete a rule
                                        5 - Delete all rules
                                        6 - Show current flows
                                        7 - Import from text file
                                        8 - Add custom CLI command 
                                        9 - Quit \n''')


if __name__ == "__main__":
    login()
    while True:
        try:
            getflows()
            ChooseAnAction()
            choice = input('Enter choice: ')
            choice = int(choice)
            if int(choice) == 1:
                newflowIPv4()
            elif int(choice) == 2:
                newflowIPv6()
            elif int(choice) == 3:
                addrule()
            elif int(choice) == 4:
                deleterule()
            elif int(choice) == 5:
                deleteallrules()
            elif int(choice) == 6:
                getflows()
            elif int(choice) == 7:
                load_from_file()
            elif int(choice) == 8:
                newflowfullcustom()
            elif int(choice) == 9:
                exit(0)
        except Exception | KeyboardInterrupt:
            print("\nInvalid Option! Available options 1-9\n")
            exit(-1)
