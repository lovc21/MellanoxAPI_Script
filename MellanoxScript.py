#!/usr/bin/python3

import requests, json, time

credentials = {"username": "<add  username>", "password": "<add password>"}
session = requests.Session()
url = "http://add.ip.address.here/admin/launch?script=json"


def login():
    global credentials
    try:
        # login and get session cookie
        r = session.post("http://add.ip.address.here/admin/launch?script=rh&template=json-request&action=json-login",
                         json=credentials)
        print("---------------------------------------------------------------------\n")
        print("LOGIN")
        print(f"{r.json()}\n")
        print(f"{session.cookies}\n")
        print("Logged in on a Mellanox switch\n")
        print("---------------------------------------------------------------------\n")
    except:
        print("login failed\n")
        exit(-1)


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
    print("please enter the openflow ID (example ID: openflow add-flows 1-1000)")
    while True:
        try:
            openflowID = input("enter openflow ID:")
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
    rules = input("enter yes to delete all rules(y/yes/Y/YES):")
    if rules == "y" or rules == "yes" or rules == "Y" or rules == "YES":
        r = session.post(url, json={"cmd": "openflow del-flows all"})
        print("\n", r.json())
        print("all flows are deleted")


def newflowfullcustom():
    global url
    while True:
        try:
            print("enter a full comand in a network switch CLI \n")
            print("example: openflow add-flows 1000 priority=50,in_port=Eth1/1,actions=output=Eth1/50\n")
            cmd1 = input("enter command:")
            if len(cmd1) != 0:
                print("---------------------------------------------------------------------\n")
                r = session.post(url, json={"cmd": cmd1})
                print("\n", r.json())
        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv4():
    global url
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
                portID = input("enter a in_port/entry port:")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("example nw_src: 10.10.2.2/24 \n")
                print("if empty this rule will not be used")
                new_srcID = input("enter a new_src IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("example nw_dst: 10.20.1.4/24\n")
                print("if empty this rule will not be used")
                new_dstID = input("enter a new_dst IP: ")
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

            ### Actions and Outputs
            elif i == 9:
                print("example of a output: Eth1/12, normal, ALL, ")
                print("if empty this rule will not be used")
                actions_outputID = input("enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 10:
                print(
                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("enrer a action:")
                print("---------------------------------------------------------------------\n")

            elif i == 11:
                try:
                    command = f"openflow add-flows "
                    if len(openflowID) > 0:
                        command = f"{command}{openflowID}"

                    if len(tableID) > 0:
                        command = f"{command} table={tableID}"

                    if len(priorityID) > 0 and len(tableID) > 0:
                        command = f" {command},priority={priorityID}"

                    if len(portID) > 0 and len(tableID) == 0:
                        command = f" {command} priority={priorityID}"

                    if len(portID) > 0:
                        command = f"{command},in_port={portID}"

                    if len(new_srcID) > 0:
                        command = f"{command},nw_src={new_srcID}"

                    if len(new_dstID) > 0:
                        command = f"{command},nw_dst={new_dstID}"

                    if len(vlanID) > 0:
                        command = f"{command},dl_vlan={vlanID}"

                    # IPv4
                    command = f"{command},dl_type=0x0800"

                    if len(nw_port) > 0:
                        command = f"{command},nw_porto={nw_port}"

                    if len(actions_outputID) > 0:
                        command = f"{command},actions=output={actions_outputID}"

                    if len(actionID) > 0:
                        command = f"{command},actions={actionID}"

                    print(command)
                    r = session.post(url, json={"cmd": f"{command}"})
                    print("\n", r.json())

                except KeyboardInterrupt:
                    print('interrupted!')
                    break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv6():
    global url
    for i in range(12):
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

            ### Actions and Outputs
            elif i == 9:
                print("example of a output: Eth1/12, normal, ALL, ")
                print("if empty this rule will not be used")
                actions_outputID = input("enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 10:
                print(
                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("enrer a action:")
                print("---------------------------------------------------------------------\n")

            elif i == 11:
                try:
                    command = f"openflow add-flows "
                    if len(openflowID) > 0:
                        command = f"{command}{openflowID}"

                    if len(tableID) > 0:
                        command = f"{command} table={tableID}"

                    if len(priorityID) > 0 and len(tableID) > 0:
                        command = f" {command},priority={priorityID}"

                    if len(portID) > 0 and len(tableID) == 0:
                        command = f" {command} priority={priorityID}"

                    if len(portID) > 0:
                        command = f"{command},in_port={portID}"

                    if len(new_srcID) > 0:
                        command = f"{command},nw_src={new_srcID}"

                    if len(new_dstID) > 0:
                        command = f"{command},nw_dst={new_dstID}"

                    if len(vlanID) > 0:
                        command = f"{command},dl_vlan={vlanID}"

                    # IPv6
                    command = f"{command},dl_type=0x86DD"

                    if len(nw_port) > 0:
                        command = f"{command},nw_porto={nw_port}"

                    if len(actions_outputID) > 0:
                        command = f"{command},actions=output={actions_outputID}"

                    if len(actionID) > 0:
                        command = f"{command},actions={actionID}"

                    print(command)
                    r = session.post(url, json={"cmd": f"{command}"})
                    print("\n", r.json())

                except KeyboardInterrupt:
                    print('interrupted!')
                    break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def addrule():
    global url
    for i in range(14):
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
                print("example nw_dst: \n")
                print("if empty this rule will not be used")
                new_dstID = input("enter a new_dst IP: ")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                print("example vlan: 16\n")
                print("if empty this rule will not be used")
                vlanID = input("enter a vlan:")
                print("---------------------------------------------------------------------\n")
            elif i == 9:
                print("example new port: 6\n")
                print("if empty this rule will not be used")
                nw_port = input("enter a new port: ")
                print("---------------------------------------------------------------------\n")
            elif i == 10:
                print("example new vlan_tci: 0x1000/0x1000\n")
                print("if empty this rule will not be used")
                vlan_tci = input("enter a new vlan_tci: ")
                print("---------------------------------------------------------------------\n")

            ### Actions and Output
            elif i == 11:
                print("example of a output: Eth1/12, normal, ALL, ")
                print("if empty this rule will not be used")
                actions_outputID = input("enter a output: ")
                print("---------------------------------------------------------------------\n")
            elif i == 12:
                print(
                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                print("example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                actionID = input("enrer a action:")
                print("---------------------------------------------------------------------\n")
            elif i == 13:
                try:
                    command = f"openflow add-flows "
                    if len(openflowID) > 0:
                        command = f"{command}{openflowID}"

                    if len(tableID) > 0:
                        command = f"{command} table={tableID}"

                    if len(priorityID) > 0 and len(tableID) > 0:
                        command = f" {command},priority={priorityID}"

                    if len(portID) > 0 and len(tableID) == 0:
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

                    if len(typeID) > 0:
                        command = f"{command},dl_type={typeID}"

                    if len(nw_port) > 0:
                        command = f"{command},nw_porto={nw_port}"

                    if len(actions_outputID) > 0:
                        command = f"{command},actions=output={actions_outputID}"

                    if len(actionID) > 0:
                        command = f"{command},actions={actionID}"

                    print(command)
                    r = session.post(url, json={"cmd": f"{command}"})
                    print("\n", r.json())

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
                                        6 - show current flows
                                        8 - add custom CLI comand 
                                        9 - Quit \n''')
    pass


if __name__ == "__main__":
    login()
    print('''Choose an action\n
                                    1 - Add simple IPv4 Rule  
                                    2 - Add simple IPv6 Rule 
                                    3 - Add custom Rule
                                    4 - Delete a rule
                                    5 - Delete all rules
                                    6 - show current flows
                                    8 - add custom CLI comand 
                                    9 - Quit \n''')
    while True:
        try:
            getflows()
            choice = input('Enter choice: ')
            choice = int(choice)
            if int(choice) == 1:
                newflowIPv4()
                ChooseAnAction()
            elif int(choice) == 2:
                newflowIPv6()
                ChooseAnAction()
            elif int(choice) == 3:
                addrule()
                ChooseAnAction()
            elif int(choice) == 4:
                deleterule()
                ChooseAnAction()
            elif int(choice) == 5:
                deleteallrules()
                ChooseAnAction()
            elif int(choice) == 6:
                getflows()
                ChooseAnAction()
            elif int(choice) == 8:
                newflowfullcustom()
                ChooseAnAction()
            elif int(choice) == 9:
                quit()
        except Exception | KeyboardInterrupt:
            print("\nInvalid Option! Available options 1-9\n")
            exit(-1)
