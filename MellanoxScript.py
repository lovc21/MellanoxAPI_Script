#!/usr/bin/python3

import requests, json, time, os
from ipaddress import ip_address, IPv4Address

credentials = {"username": "<username>", "password": "<password>"}
session = requests.Session()
url = "http://<ip_address>/admin/launch?script=json"
newOpenFlow = 1
data = ""


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
    except:
        print("login failed\n")
        exit(-1)


def loadfromfile():
    while True:
        try:
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
                    tp_dst = ""
                    ipv6_src = ""
                    actionID = ""
                    priorityID = ""
                    portID = ""
                    nw_proto = ""
                    tp_src = ""
                    actions_outputID = ""
                    ipv6_dst = ""
                    tcp_src = ""
                    tcp_dst = ""
                    udp_src = ""
                    udp_dst = ""
                    portIDIPv6 = ""
                    ICMPV4_CODE = ""
                    ICMPV4_TYPE = ""
                    ICMPV6_TYPE = ""
                    ICMPV6_CODE = ""
                    SCTP_SRC = ""
                    SCTP_DST = ""
                    possibleOpenflowID = str(newOpenFlow)
                    commands = line.replace(" ", "").split("|")
                    for key_value in commands:
                        key_value = key_value.split("=")
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
                                        tcp_dst = key_value[index + 1]
                                if key_value[index] == "ipv6_src":
                                    if len(key_value[index + 1]) > 0:
                                        ipv6_src = key_value[index + 1]
                                if key_value[index] == "actions":
                                    if len(key_value[index + 1]) > 0:
                                        # actions=set_field:6297->vlan_vid,output:25,output:52,output:54
                                        actionID = key_value[index + 1].replace("output:", "output=Eth1/").replace("\n",
                                                                                                                   "")
                                        print(actionID)
                            else:
                                # skipaš vse lihe elemente k so vrednosti
                                continue
                    try:
                        add_flow(openflowID=possibleOpenflowID, priorityID=priorityID, tableID=tableID,
                                 portID=portID,
                                 new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, vlan_tci=vlan_tci,
                                 typeID=typeID, ipv6_src=ipv6_src, nw_proto=nw_proto,
                                 actions_outputID=actions_outputID, actionID=actionID, ipv6_dst=ipv6_dst,
                                 tcp_src=tcp_src,
                                 tcp_dst=tcp_dst, udp_src=udp_src, udp_dst=udp_dst, portIDIPv6=portIDIPv6,
                                 ICMPV4_CODE=ICMPV4_CODE, ICMPV4_TYPE=ICMPV4_TYPE, ICMPV6_TYPE=ICMPV6_TYPE,
                                 ICMPV6_CODE=ICMPV6_CODE, SCTP_SRC=SCTP_SRC, SCTP_DST=SCTP_DST)
                    except Exception as ex:
                        print(ex)
                        break
        except KeyboardInterrupt:
            print("interrupted")
            break


def add_flow(openflowID, tableID, priorityID, portID, new_srcID, new_dstID, vlanID, vlan_tci, typeID, tcp_src, tcp_dst,
             nw_proto,
             udp_src, udp_dst, ipv6_src, ipv6_dst,
             actions_outputID, actionID, portIDIPv6, ICMPV4_CODE, ICMPV4_TYPE, ICMPV6_TYPE, ICMPV6_CODE, SCTP_SRC,
             SCTP_DST):
    global data
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
        command = f"{command},ip,nw_src={new_srcID}"
    if len(new_dstID) > 0:
        if len(new_srcID) == 0:
            command = f"{command},ip,nw_dst={new_dstID}"
        else:
            command = f"{command},nw_dst={new_dstID}"
    if len(vlanID) > 0:
        command = f"{command},dl_vlan={vlanID}"
    if len(vlan_tci) > 0:
        command = f"{command},vlan_tci={vlan_tci}"
    if len(nw_proto) > 0:
        if int(nw_proto) == 6:
            if len(tcp_dst) > 0:
                command = f"{command},nw_proto=6,tcp_dst={tcp_dst}"
            if len(tcp_src) > 0:
                command = f"{command},nw_proto=6,tcp_src={tcp_src}"
            if tcp_src == "" and tcp_dst == "":
                command = f"{command},nw_proto=6"
        if int(nw_proto) == 17:
            if len(udp_dst) > 0:
                command = f"{command},nw_proto=17,udp_dst={udp_dst}"
            if len(udp_src) > 0:
                command = f"{command},nw_proto=17,udp_src={udp_src}"
            if udp_src == "" and udp_dst == "":
                command = f"{command},nw_proto=17"
        if int(nw_proto) == 1:
            if len(ICMPV4_TYPE) > 0:
                command = f"{command},nw_proto=1,icmpv4_type={ICMPV4_TYPE}"
            if len(ICMPV4_CODE) > 0:
                command = f"{command},nw_proto=1,icmpv4_code={ICMPV4_CODE}"
            if ICMPV4_TYPE == "" and ICMPV4_CODE == "":
                command = f"{command},nw_proto=1"
        if int(nw_proto) == 58:
            if len(ICMPV6_TYPE) > 0:
                command = f"{command},nw_proto=58,icmpv6_type={ICMPV6_TYPE}"
            if len(ICMPV6_CODE) > 0:
                command = f"{command},nw_proto=58,icmpv6_code={ICMPV6_CODE}"
            if ICMPV6_TYPE == "" and ICMPV6_CODE == "":
                command = f"{command},nw_proto=58"
        if int(nw_proto) == 132:
            if len(SCTP_SRC) > 0:
                command = f"{command},nw_proto=132,sctp_src={SCTP_SRC}"
            if len(SCTP_DST) > 0:
                command = f"{command},nw_proto=132,sctp_dst={SCTP_DST}"
            if len(SCTP_SRC) < 0 and len(SCTP_DST) < 0:
                command = f"{command},nw_proto=132"
    if len(ipv6_src) > 0:
        command = f"{command},dl_type=0x86DD,ipv6_src={ipv6_src}"
    if len(ipv6_dst) > 0:
        command = f"{command},dl_type=0x86DD,ipv6_dst={ipv6_dst}"
    if len(typeID) > 0:
        command = f"{command},dl_type={typeID}"
    if len(actions_outputID) > 0:
        command = f"{command},actions=output={actions_outputID}"
    if len(actionID) > 0:
        command = f"{command},actions={actionID}"

    # if typeID == "0x86DD":
    # if len(tableID) <= 0:
    # r = session.post(url, json={"cmd": f"openflow add-flows {str(int(openflowID)+1)} table=0,priority=1,in_port={portIDIPv6},actions=goto_table:10"})
    # else:
    # r = session.post(url, json={"cmd": f"openflow add-flows {str(int(openflowID)+1)} table=0,priority=1,in_port={portIDIPv6},actions=goto_table:{tableID}"})

    print(command)
    r = session.post(url, json={"cmd": f"{command}"})
    data = r.json()
    print("\n", r.json())

    if str(data["status_message"]) != "":
        getflows()
        print("---------------------------------------------------------------------\n")
        print("Wrong input !:\n")
        print("ERROR:", str(data["status_message"]))
        print(command)
        print("---------------------------------------------------------------------\n")
    else:
        getflows()


def IPv6Tabeleadder():
    global url, newOpenFlow
    r = session.post(url, json={
        "cmd": "openflow add-flows 1 table=0,priority=1,in_port=ANY,dl_type=0x86DD,actions=goto_table:10"})
    print("\n", r.json())
    pass


def add_match_keys():
    global url
    while True:
        try:
            for i in range(4):
                if i == 1:
                    print("---------------------------------------------------------------------\n")
                    print("example: 1-249\n")
                    tablenumber = input("enter a table number[empty]:")
                    print("---------------------------------------------------------------------\n")
                elif i == 2:
                    print("---------------------------------------------------------------------\n")
                    print("example: dl_type, in_port, ip_proto, ipv6_dst, ipv6_src, l4_dst_port, l4_src_port\n")
                    match_keys = input("enter a match key :")
                    print("---------------------------------------------------------------------\n")
                elif i == 3:
                    r = session.post(url, json={"cmd": f"openflow table {tablenumber} match-keys {match_keys}"})
                    print("\n", r.json())

        except KeyboardInterrupt:
            print('interrupted!')
            break


def validIPAddress(ip):
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"


def getflows():
    global url, newOpenFlow
    r = session.post(url, json={"cmd": "show openflow flows locally-configured"})
    print("---------------------------------------------------------------------\n")
    print("current flows :\n", )
    prettify_json(r.json()["data"], "flow ID", "")
    print("---------------------------------------------------------------------\n")
    taken_flow_ids = r.json()["data"].keys()
    newOpenFlow = find_min_available_value(taken_flow_ids)


def prettify_json(json: dict, key_prefix: str, value_prefix: str):
    for key in sorted(json.keys(), key=lambda x: int(x)):
        print(f"{key_prefix}: {key}; {value_prefix}: {json[key]} \n ")


def find_min_available_value(taken_flow_ids: dict) -> int:
    lastOpenFlowId = 1
    for flow_id in sorted(taken_flow_ids, key=lambda x: int(x)):
        if str(int(flow_id) + 1) in taken_flow_ids:
            continue
        else:
            lastOpenFlowId = int(flow_id) + 1
            break
    return lastOpenFlowId


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
                getflows()
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
        getflows()


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


def show_openflow_table():
    global url, newOpenFlow
    while True:
        try:
            print("---------------------------------------------------------------------\n")
            tablenumber_show = input("enter a table number[empty]:")
            print("---------------------------------------------------------------------\n")

            ##uredit json format

            if len(tablenumber_show) != 0:
                print("---------------------------------------------------------------------\n")
                r = session.post(url, json={"cmd": f"show openflow table {tablenumber_show} match-keys"})
                print("\n", r.json())

        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv4():
    global url
    possibleOpenflowID = str(newOpenFlow)
    openflowID = ""
    priorityID = ""
    tableID = ""
    portID = ""
    vlanID = ""
    new_srcID = ""
    new_dstID = ""
    actions_outputID = ""
    actionID = ""
    vlan_tci = ""
    nw_proto = ""
    tcp_src = ""
    tcp_dst = ""
    udp_src = ""
    udp_dst = ""
    typeID = "0x0800"
    ipv6_src = ""
    ipv6_dst = ""
    portIDIPv6 = ""
    ICMPV4_CODE = ""
    ICMPV4_TYPE = ""
    ICMPV6_TYPE = ""
    ICMPV6_CODE = ""
    SCTP_SRC = ""
    SCTP_DST = ""
    for i in range(13):
        try:
            ### Params
            if i == 1:
                print("example: 1-100\n")
                openflowID = input(f"enter openflow add-flows id[{possibleOpenflowID}]:")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("example: 1-1000\n")
                priorityID = input("enter a priority [1]: ")
                print("---------------------------------------------------------------------\n")

            elif i == 3:
                print("example: 1-249\n")
                tableID = input("enter table[0]: ")
                print("---------------------------------------------------------------------\n")
                if tableID == "":
                    tableID = "0"
            ###  Match
            elif i == 4:
                print("example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                print("if empty this variable will not be used")
                portID = input("enter a in_port/entry port[empty]:")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("example vlan: 16\n")
                print("if empty this variable will not be used")
                vlanID = input("enter a vlan[empty]:")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("example nw_src: 10.10.2.2/24 \n")
                print("if empty this variable will not be used")
                new_srcID = input("enter a new_src IP[empty]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 7:
                print("example nw_dst: 10.20.1.4/24\n")
                print("if empty this variable will not be used")
                new_dstID = input("enter a new_dst IP[empty]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                pass
                # print("example nw proto: 6 for TCP, 17 for UDP\n")
                # print("if empty this variable will not be used")
                # nw_proto = input("enter a nw proto:")
                # print("---------------------------------------------------------------------\n")
            elif i == 9:
                pass
                # print("example tp_src: \n")
                # print("if empty this variable will not be used")
                # tp_src = input("enter a tp_src:")
                # print("---------------------------------------------------------------------\n")
            elif i == 10:
                pass
                # print("example tp_dst: \n")
                # print("if empty this variable will not be used")
                # tp_dst = input("enter a tp_dst:")
                # print("---------------------------------------------------------------------\n")
            elif i == 11:
                pass
                # print("example new vlan_tci: 0x1000/0x1000\n")
                # print("if empty this variable will not be used")
                # vlan_tci = input("enter a new vlan_tci: ")
                # print("---------------------------------------------------------------------\n")
            ###Actions and Outputs
            elif i == 12:
                print("example of a output: Eth1/12, normal, ALL, ")
                print(
                    "if you want to a more specific action (Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue ...) leave this field empty")
                actions_outputID = input("enter a output[empty]: ")
                print("---------------------------------------------------------------------\n")
                for i in range(3):
                    try:
                        if i == 1:
                            if actions_outputID == "":
                                print(
                                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                                print("example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                                actionID = input("enrer a action[empty]:")
                                print("---------------------------------------------------------------------\n")
                            else:
                                pass
                        elif i == 2:
                            try:
                                typeID = "0x0800"
                                ipv6_src = ""
                                ipv6_dst = ""
                                if priorityID == "":
                                    priorityID = "1"
                                if openflowID == "":
                                    openflowID = possibleOpenflowID
                                add_flow(openflowID=openflowID, tableID=tableID, priorityID=priorityID, portID=portID,
                                         new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, nw_proto=nw_proto,
                                         vlan_tci=vlan_tci, typeID=typeID, actions_outputID=actions_outputID,
                                         ipv6_src=ipv6_src, ipv6_dst=ipv6_dst, actionID=actionID, tcp_src=tcp_src,
                                         tcp_dst=tcp_dst, udp_src=udp_src, udp_dst=udp_dst, portIDIPv6=portIDIPv6,
                                         ICMPV4_CODE=ICMPV4_CODE, ICMPV4_TYPE=ICMPV4_TYPE, ICMPV6_TYPE=ICMPV6_TYPE,
                                         ICMPV6_CODE=ICMPV6_CODE, SCTP_SRC=SCTP_SRC, SCTP_DST=SCTP_DST)
                            except KeyboardInterrupt:
                                print('interrupted!')
                                break
                    except KeyboardInterrupt:
                        print('interrupted!')
                        break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def newflowIPv6():
    global url
    openflowID = ""
    possibleOpenflowID = str(newOpenFlow)
    priorityID = ""
    tableID = "10"
    portID = ""
    vlanID = ""
    ipv6_src = ""
    ipv6_dst = ""
    actions_outputID = ""
    actionID = ""
    tcp_src = ""
    tcp_dst = ""
    udp_src = ""
    udp_dst = ""
    vlan_tci = ""
    nw_proto = ""
    typeID = "0x86DD"
    new_srcID = ""
    new_dstID = ""
    portIDIPv6 = ""
    ICMPV4_CODE = ""
    ICMPV4_TYPE = ""
    ICMPV6_TYPE = ""
    ICMPV6_CODE = ""
    SCTP_SRC = ""
    SCTP_DST = ""
    for i in range(13):
        try:
            ### Params
            if i == 1:
                print("IMPORTANT remember the openflow id")
                print("example: 1-100\n")
                openflowID = input(f"enter openflow add-flows id[{possibleOpenflowID}]:")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("example: 1-1000\n")
                priorityID = input("enter a priority[1]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 3:
                print("example: 1-249\n")
                tableID = input("enter table[10]: ")
                if tableID == "":
                    tableID = "10"
                print("---------------------------------------------------------------------\n")
            ###  Match
            elif i == 4:
                print("example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                print("if empty this variable will not be used")
                portIDIPv6 = input("enter a in_port/entry port[empty]:")
                print("---------------------------------------------------------------------\n")
            elif i == 5:
                print("example vlan: 16\n")
                print("if empty this variable will not be used")
                vlanID = input("enter a vlan[empty]:")
                print("---------------------------------------------------------------------\n")
            elif i == 6:
                print("example nw_src_IPv6:0eb6:1385:6749:4147:12bc:745f:3448:ec90\n")
                print("if empty this variable will not be used")
                ipv6_src = input("enter a new_src IPv6[empty]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 7:
                print("example nw_dst_IPv6:0eb6:1385:6749:4147:12bc:745f:3448:ec90\n")
                print("if empty this variable will not be used")
                ipv6_dst = input("enter a new_dst IPv6[empty]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 8:
                pass
                # print("example nw proto: 6 for TCP, 17 for UDP\n")
                # print("if empty this variable will not be used")
                # nw_proto = input("enter a nw proto: ")
                # print("---------------------------------------------------------------------\n")
            elif i == 9:
                pass
                # print("example tp_src: \n")
                # print("if empty this variable will not be used")
                # tp_src = input("enter a tp_src: ")
                # print("---------------------------------------------------------------------\n")
            elif i == 10:
                pass
                # print("example tp_dst: \n")
                # print("if empty this variable will not be used")
                # tp_dst = input("enter a tp_dst:")
                # print("---------------------------------------------------------------------\n")
            elif i == 11:
                pass
                # print("example new vlan_tci: 0x1000/0x1000\n")
                # print("if empty this variable will not be used")
                # vlan_tci = input("enter a new vlan_tci: ")
                # print("---------------------------------------------------------------------\n")
            ### Actions and Outputs
            elif i == 12:
                print("example of a output: Eth1/12, normal, ALL, ")
                print(
                    "if you want to a more specific action (Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue ...) leave this field empty")
                actions_outputID = input("enter a output[empty]: ")
                print("---------------------------------------------------------------------\n")
                for i in range(3):
                    try:
                        if i == 1:
                            if actions_outputID == "":
                                print(
                                    "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                                print("example of an action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                                actionID = input("enter an action[empty]:")
                                print("---------------------------------------------------------------------\n")
                            else:
                                pass
                        elif i == 2:
                            try:
                                if priorityID == "":
                                    priorityID = "1"
                                if openflowID == "":
                                    openflowID = possibleOpenflowID
                                add_flow(openflowID=openflowID, tableID=tableID, priorityID=priorityID, portID=portID,
                                         new_srcID=new_srcID, new_dstID=new_dstID, vlanID=vlanID, nw_proto=nw_proto,
                                         tcp_src=tcp_src, tcp_dst=tcp_dst, udp_src=udp_src, udp_dst=udp_dst,
                                         vlan_tci=vlan_tci, typeID=typeID,
                                         actions_outputID=actions_outputID, ipv6_src=ipv6_src, ipv6_dst=ipv6_dst,
                                         actionID=actionID, portIDIPv6=portIDIPv6, ICMPV4_TYPE=ICMPV4_TYPE,
                                         ICMPV4_CODE=ICMPV4_CODE, ICMPV6_TYPE=ICMPV6_TYPE, ICMPV6_CODE=ICMPV6_CODE,
                                         SCTP_SRC=SCTP_SRC, SCTP_DST=SCTP_DST)
                            except KeyboardInterrupt:
                                print('interrupted!')
                                break
                    except KeyboardInterrupt:
                        print('interrupted!')
                        break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def addrule():
    global url
    typeID = "0x0800"
    possibleOpenflowID = str(newOpenFlow)
    openflowID = ""
    priorityID = ""
    tableID = ""
    portID = ""
    vlanID = ""
    new_srcID = ""
    new_dstID = ""
    nw_proto = ""
    tcp_src = ""
    tcp_dst = ""
    udp_src = ""
    udp_dst = ""
    vlan_tci = ""
    ipv6_dst = ""
    ipv6_src = ""
    actionID = ""
    actions_outputID = ""
    portIDIPv6 = ""
    ICMPV4_CODE = ""
    ICMPV4_TYPE = ""
    ICMPV6_TYPE = ""
    ICMPV6_CODE = ""
    SCTP_SRC = ""
    SCTP_DST = ""
    for i in range(5):
        try:
            ### Params
            if i == 1:
                print("IMPORTANT remember the openflow id")
                print("example: 1-100\n")
                openflowID = input(f"enter openflow add-flows id[{possibleOpenflowID}]:")
                print("---------------------------------------------------------------------\n")
            elif i == 2:
                print("example: 1-1000\n")
                priorityID = input("enter a priority[1]: ")
                print("---------------------------------------------------------------------\n")
            elif i == 3:
                print("example: 1-249\n")
                tableID = input("enter table[0]: ")
                if tableID == "":
                    tableID = "0"
                print("---------------------------------------------------------------------\n")
            ###  Match stvari
            elif i == 4:
                print("example entry port: Eth1/1; Eth1/22, Eth1/23, Eth1/24; ANY)\n")
                portID = input("enter a in_port/entry port[empty]:")
                portIDIPv6 = portID
                print("---------------------------------------------------------------------\n")
                for i in range(6):
                    try:
                        if i == 1:
                            print("example vlan: 16\n")
                            print("if empty this variable will not be used")
                            vlanID = input("enter a vlan[empty]:")
                            print("---------------------------------------------------------------------\n")
                        elif i == 2:
                            print("example EtherType: 0x0800 == IPv4, 0x0806 == ARP, 0x86DD ==IPv6, ")
                            typeID = input("enter a packet type[IPv4]: ")
                            print("---------------------------------------------------------------------\n")
                            if typeID == "":
                                typeID = "0x0800"
                            else:
                                pass
                        elif i == 3:
                            if typeID == "0x0800":
                                print("example nw_src IPv4: \n")
                                print("if empty this variable will not be used")
                                new_srcID = input("enter a new_src IP[empty]: ")
                                print("---------------------------------------------------------------------\n")
                            else:
                                new_srcID = ""
                                pass
                        elif i == 4:
                            if typeID == "0x0800":
                                print("example nw_dst IPv4: \n")
                                print("if empty this variable will not be used")
                                new_dstID = input("enter a new_dst IP[empty]: ")
                                print("---------------------------------------------------------------------\n")
                            else:
                                new_dstID = ""
                                pass
                        elif i == 5:
                            print("example nw proto: 6 for TCP, 17 for UDP, 1 for ICMP, 58 for ICMPv6, 132 for sctp\n")
                            print("if empty this variable will not be used")
                            nw_proto = input("enter a nw_proto[empty]: ")
                            print("---------------------------------------------------------------------\n")
                            for i in range(15):
                                try:
                                    if i == 1:
                                        if nw_proto != "":
                                            if nw_proto == "6":

                                                print("if empty this variable will not be used")
                                                tcp_src = input("enter a tcp_src[empty]: ")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                tcp_src = ""
                                                pass
                                        else:
                                            tcp_src = ""
                                            pass
                                    elif i == 2:
                                        if nw_proto != "":
                                            if nw_proto == "6":
                                                print("if empty this variable will not be used")
                                                tcp_dst = input("enter a tcp_dst[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                tcp_dst = ""
                                                pass
                                        else:
                                            tcp_dst = ""
                                            pass
                                    elif i == 3:
                                        if nw_proto != "":
                                            if nw_proto == "17":
                                                print("if empty this variable will not be used")
                                                udp_src = input("enter a udp_src[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                udp_src = ""
                                                pass
                                        else:
                                            udp_src = ""
                                            pass
                                    elif i == 4:
                                        if nw_proto != "":
                                            if nw_proto == "17":
                                                print("if empty this variable will not be used")
                                                udp_dst = input("enter udp_dst[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                udp_dst = ""
                                                pass
                                        else:
                                            udp_dst = ""
                                            pass
                                    elif i == 5:
                                        if nw_proto != "":
                                            if nw_proto == "1":
                                                print("if empty this variable will not be used")
                                                ICMPV4_TYPE = input("enter icmpv4_type[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                ICMPV4_TYPE = ""
                                                pass
                                        else:
                                            ICMPV4_TYPE = ""
                                            pass
                                    elif i == 6:
                                        if nw_proto != "":
                                            if nw_proto == "1":
                                                print("if empty this variable will not be used")
                                                ICMPV4_CODE = input("enter icmpv4_code[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                ICMPV4_CODE = ""
                                                pass
                                        else:
                                            ICMPV4_CODE = ""
                                            pass
                                    elif i == 7:
                                        if nw_proto != "":
                                            if nw_proto == "132":
                                                print("if empty this variable will not be used")
                                                SCTP_SRC = input("enter SCTP_SRC[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                SCTP_SRC = ""
                                                pass
                                        else:
                                            SCTP_SRC = ""
                                            pass
                                    elif i == 8:
                                        if nw_proto != "":
                                            if nw_proto == "132":
                                                print("if empty this variable will not be used")
                                                SCTP_DST = input("enter SCTP_DST[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                SCTP_DST = ""
                                                pass
                                        else:
                                            SCTP_DST = ""
                                            pass
                                    elif i == 9:
                                        if nw_proto != "":
                                            if nw_proto == "58":
                                                print("if empty this variable will not be used")
                                                ICMPV6_TYPE = input("enter ICMPV6_TYPE[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                ICMPV6_TYPE = ""
                                                pass
                                        else:
                                            ICMPV6_TYPE = ""
                                            pass
                                    elif i == 10:
                                        if nw_proto != "":
                                            if nw_proto == "58":
                                                print("if empty this variable will not be used")
                                                ICMPV6_CODE = input("enter ICMPV6_CODE[empty]:")
                                                print(
                                                    "---------------------------------------------------------------------\n")
                                            else:
                                                ICMPV6_CODE = ""
                                                pass
                                        else:
                                            ICMPV6_CODE = ""
                                            pass
                                    elif i == 11:
                                        print("example new vlan_tci: 0x1000/0x1000\n")
                                        print("if empty this variable will not be used")
                                        vlan_tci = input("enter a new vlan_tci[empty]: ")
                                        print("---------------------------------------------------------------------\n")
                                    elif i == 12:
                                        if typeID == "0x86DD":
                                            print("example nw_src IPv6: :00:0c:e9:00:00:01 \n")
                                            print("if empty this variable will not be used")
                                            ipv6_src = input("enter a new_src IPv6[empty]: ")
                                            print(
                                                "---------------------------------------------------------------------\n")
                                        else:
                                            pass
                                    elif i == 13:
                                        if typeID == "0x86DD":
                                            print("example nw_dst IPv6: :00:0c:e9:00:00:01\n")
                                            print("if empty this variable will not be used")
                                            ipv6_dst = input("enter a new_dst IPv6[empty]: ")
                                            print(
                                                "---------------------------------------------------------------------\n")
                                        else:
                                            pass
                                    ### Actions and Output
                                    elif i == 14:
                                        print("example of a output: Eth1/12, normal, ALL, ")
                                        print(
                                            "if you want to a more specific action (Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue ...) leave this field empty")
                                        actions_outputID = input("enter a output[empty]: ")
                                        print("---------------------------------------------------------------------\n")
                                        for i in range(3):
                                            try:
                                                if i == 1:
                                                    if len(actions_outputID) == 0:
                                                        print(
                                                            "action's: Push/pop VLAN, SET_TTL, DEC_TTL, goto_table, Set queue, VLAN ID, PCP, DSCP, ECN, Output, Group, Meters, Normal, DROP, OUTPUT, DEC_TTL, SET_DMAC, OUTPUT\n")
                                                        print(
                                                            "example of a action: pop_vlan, goto_table:251, od_nw_ttl:55, Set_field:")
                                                        actionID = input("enrer a action[empty]:")
                                                        print(
                                                            "---------------------------------------------------------------------\n")
                                                    else:
                                                        pass
                                                elif i == 2:
                                                    try:
                                                        if priorityID == "":
                                                            priorityID = "1"
                                                        if openflowID == "":
                                                            openflowID = possibleOpenflowID
                                                        add_flow(openflowID=openflowID, tableID=tableID,
                                                                 priorityID=priorityID,
                                                                 portID=portID,
                                                                 new_srcID=new_srcID, new_dstID=new_dstID,
                                                                 vlanID=vlanID,
                                                                 vlan_tci=vlan_tci,
                                                                 typeID=typeID, nw_proto=nw_proto, tcp_src=tcp_src,
                                                                 tcp_dst=tcp_dst, udp_src=udp_src, udp_dst=udp_dst,
                                                                 ipv6_src=ipv6_src, ipv6_dst=ipv6_dst,
                                                                 actions_outputID=actions_outputID,
                                                                 actionID=actionID, portIDIPv6=portIDIPv6,
                                                                 ICMPV4_TYPE=ICMPV4_TYPE, ICMPV4_CODE=ICMPV4_CODE,
                                                                 ICMPV6_TYPE=ICMPV6_TYPE, ICMPV6_CODE=ICMPV6_CODE,
                                                                 SCTP_SRC=SCTP_SRC, SCTP_DST=SCTP_DST)

                                                    except KeyboardInterrupt:
                                                        print('interrupted!')
                                                        break
                                            except KeyboardInterrupt:
                                                print('interrupted!')
                                                break
                                except KeyboardInterrupt:
                                    print('interrupted!')
                                    break
                    except KeyboardInterrupt:
                        print('interrupted!')
                        break
        except KeyboardInterrupt:
            print('interrupted!')
            break


def ChooseAnAction():
    print('''Choose an action:\n
                                                    ACTIONs
                                    ________________________________________
                                    |                                      |
                                    |    1  - Add simple IPv4 Rule         | 
                                    |    2  - Add simple IPv6 Rule         |
                                    |    3  - Add custom Rule              |
                                    |    4  - Delete a rule                |     
                                    |    5  - Delete all rules             |
                                    |    6  - Show current flows           | 
                                    |    7  - Import from text file        |
                                    |    8  - Add custom CLI command       |
                                    |    9  - Add match-keys for a table   | 
                                    |    10 - show table match keys        |
                                    |    11 - Quit                         |   
                                    |                                      |
                                    ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯                                       \n''')


if __name__ == "__main__":
    login()
    IPv6Tabeleadder()
    getflows()
    while True:
        try:
            # getflows()
            ChooseAnAction()
            choice = input('Enter choice: ')
            choice.strip()
            if choice == "1":
                newflowIPv4()
            elif choice == "2":
                newflowIPv6()
            elif choice == "3":
                addrule()
            elif choice == "4":
                deleterule()
            elif choice == "5":
                deleteallrules()
            elif choice == "6":
                getflows()
            elif choice == "7":
                loadfromfile()
            elif choice == "8":
                newflowfullcustom()
            elif choice == "9":
                add_match_keys()
            elif choice == "10":
                show_openflow_table()
            elif choice == "11":
                quit()
            else:
                print("That is not a valid choice \n")
                print("Enter a number (1-9) \n ")
                time.sleep(1)
        except Exception | KeyboardInterrupt:
            print("\nInvalid Option! Available options 1-9\n")
