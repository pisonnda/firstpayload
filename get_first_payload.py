#!/usr/bin/python3
#Version1: 2024.05.29 (CQTVQP)
##Get: session,time_stamp,protocol,payload's content

import pandas as pd
import pyshark 
import sys

from collections import defaultdict
from datetime import datetime
from tqdm import tqdm


initial_sessions = {}
def get_ini_payloads(cap, pcap_count, pcap_file):
    bar = tqdm(total = pcap_count, desc=pcap_file, position=0)
    for pkt in cap:
        bar.update()
        timestamp = float(pkt.sniff_timestamp)
        timestamp = round(timestamp)
        try:
            session_index = pkt.tcp.stream 
            #Source and Destination IP Address and Ports
            srcip = pkt.ip.src
            dstip = pkt.ip.dst
            sport = pkt.tcp.srcport
            dport = pkt.tcp.dstport
            if session_index not in initial_sessions:
                initial_sessions[session_index] = [srcip, sport, dstip, dport, str(timestamp), str(timestamp), None]
            else:
                initial_sessions[session_index][5] = str(timestamp)
            try: 
                raw_payload = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
            except:
                continue

            if initial_sessions[session_index][6] != None: 
                continue
            else:
                initial_sessions[session_index][6] = raw_payload
        except: continue

    for k,v in initial_sessions.items():
            if initial_sessions[k][6] != None:
                print(k, end=',')
                print(','.join(v))

def get_all_payloads(cap):
    for pkt in cap: 
        sentence = []
        session_index = pkt.tcp.stream
        sentence.append(session_index)
        timestamp = float(pkt.sniff_timestamp)
        sentence.append(timestamp)
        dport = pkt.tcp.dstport
        sentence.append(dport)
        try:
            raw_payload = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
            sentence.append(raw_payload)
        except:
            continue
        phrase.append(sentence)

    for c in phrase:
        print(c)


def make_base(base_file):
    base_dict = {}
    fp = open(base_file, "r")
    #Header:        SRCIP, SPORT, DSTIP, DPORT: STIME, LTIME, CATEGORY, ANOMARY
    buf = fp.readlines()
    for line in buf:
        line = line.rstrip()
        fields = line.split(",")
        #key = ",".join(fields[:6])
        key = ",".join(fields[:4])
        #print(key)
        value = fields[4:]
        if key in base_dict: 
            if base_dict[key] == value: continue
                #print("Duplicated!!!", end=':\t')
                #print(key)
            base_dict[key][1] = value[1]
        else:
            base_dict[key] = value
    #print(len(base_dict))
    return base_dict

def matching(match_file, base_dict):
    fp = open(match_file, 'r')
    #Header:        SESSION, SRCIP, SPORT, DSTIP, DPORT, STIME, LTIME, PAYLOAD
    buf = fp.readlines()
    bar = tqdm(total = len(buf), desc=match_file, position=0)
    for line in buf:
        bar.update()
        line = line.rstrip()
        line = line.split(",")
        #key = ",".join(line[1:7])
        key = ",".join(line[1:5])
        #print(key)
        if key in base_dict:
            #print(f"{line[0]},{key},{line[7]}", end=',')
            if (int(base_dict[key][0]) <= int(line[5])) & (int(line[6]) - 1 <= int(base_dict[key][1])):
                print(f"{line[7]}", end=',')
                print(','.join(base_dict[key][2:]))
                #print()
            #else:
            #    print("No matching:", end='')
            #    print(f"{line[0]},{key},{line[5:]}")
            #    #print()

def main():
    option = sys.argv[1]
    #print(" ".join(sys.argv))

    if option == '-i':
        pcap_file = sys.argv[2]
        pcap_count = int(sys.argv[3])
        cap = pyshark.FileCapture(pcap_file)
        sess_index = [] # to save stream indexes in an array
        phrase = []
        get_ini_payloads(cap, pcap_count, pcap_file)
    elif option == '-l':
        base_dict = make_base("/data/Dataset/05_UNSW_NB15/CSV_Files/new_base.csv")
        csv_files = sys.argv[2:]
        for csv_file in csv_files:
            matching(csv_file, base_dict)
    else:
        print("Syntax Error")
        print("Choose option: Get Initial Payloads (-i), Get label for Initial Payloads (-l)")
        sys.exit()

if __name__ == '__main__':
    main()
