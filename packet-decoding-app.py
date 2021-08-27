from typing import Protocol
from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
import requests
import os
import threading
import time
import logging
from datetime import datetime
import requests
import json
from pickle import dump, load
import sklearn
sns.set(color_codes=True)
#%matplotlib inline

"""
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
02 04 05 a0 01 03 03 05 01 01 08 0a 1d 74 65 c5 00 00 00 00 04 02 00 00
"""

'''
0,tcp,private,REJ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,1,0.00,0.00,1.00,1.00,0.50,1.00,0.00,255,1,0.00,0.31,0.28,0.00,0.00,0.00,0.29,1.00,portsweep,20
'''

'''
Categorical Features to match

['protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
       'service_IRC', 'service_X11', 'service_Z39_50', 'service_aol',
       'service_auth', 'service_bgp', 'service_courier', 'service_csnet_ns',
       'service_ctf', 'service_daytime', 'service_discard', 'service_domain',
       'service_domain_u', 'service_echo', 'service_eco_i', 'service_ecr_i',
       'service_efs', 'service_exec', 'service_finger', 'service_ftp',
       'service_ftp_data', 'service_gopher', 'service_harvest',
       'service_hostnames', 'service_http', 'service_http_2784',
       'service_http_443', 'service_http_8001', 'service_imap4',
       'service_iso_tsap', 'service_klogin', 'service_kshell', 'service_ldap',
       'service_link', 'service_login', 'service_mtp', 'service_name',
       'service_netbios_dgm', 'service_netbios_ns', 'service_netbios_ssn',
       'service_netstat', 'service_nnsp', 'service_nntp', 'service_ntp_u',
       'service_other', 'service_pm_dump', 'service_pop_2', 'service_pop_3',
       'service_printer', 'service_private', 'service_red_i',
       'service_remote_job', 'service_rje', 'service_shell', 'service_smtp',
       'service_sql_net', 'service_ssh', 'service_sunrpc', 'service_supdup',
       'service_systat', 'service_telnet', 'service_tftp_u', 'service_tim_i',
       'service_time', 'service_urh_i', 'service_urp_i', 'service_uucp',
       'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_OTH',
       'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0',
       'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']
'''

'''
Normal Flags

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

Dataset Flags

– S0: Connection attempt seen, no reply.
– S1: Connection established, not terminated.
– SF: Normal establishment and termination.
– REJ: Connection attempt rejected.
– S2: Connection established and close attempt by originator seen (but no
reply from responder).
– S3: Connection established and close attempt by responder seen (but no
reply from originator).
– RSTO: Connection established, originator aborted (sent a RST).
– RSTR: Established, responder aborted.
– RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYN
ACK from the responder.
– RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a
SYN from the (purported) originator.
– SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK
from the responder (hence the connection was “half” open).
– SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN
from the originator.
– OTH: No SYN seen, just midstream traffic (a “partial connection” that was
not later closed).

reference
J. Song, H. Takakura, Y. Okabe, Description of Kyoto University Benchmark Data, Tech. rep., National Institute of Information and Communications Technology (NICT) (2010)

'''

user_hot_list = ['root', 'admin', 'user', 'test', 'ubuntu', 'ubnt', 'support', 'oracle', 'pi', 'Guest', 'postgres', 'ftpuser', 'usuario', 'nagios', '1234',
'ftp', 'operator', 'git', 'hadoop', 'ts3', 'teamspeak', 'mysql', 'tomcat', 'service', 'butter', 'ts', 'bot', 'deploy', 'monitor', 'administrator', 'bin', 'default',
'adm', 'vagrant', 'uucp', 'www', 'jenkins', 'apache', 'sshd', 'PlcmSplp', 'cisco', 'sinusbot', 'user1', 'backup', 'Management', 'steam', 'mother', 'dev', 'zabbix',
'manager', 'teamspeak3', 'nobody', 'csgoserver', 'test2', 'demo', '0', 'a', 'minecraft', 'alex', 'postfix', 'glassfish', 'jboss', 'master', 'ghost', 'vnc', 'info',
'111111', 'debian', 'centos', 'testuser', 'system', 'www-data', 'test1', 'upload', 'picmspip', 'weblogic', 'redhat', 'developer', 'public', 'student', 'webmaster',
'osmc', 'c', 'server', 'supervisor', '22', 'hdfs', 'linux', 'postmaster', 'csserver', 'prueba', 'matt', 'vyayya', 'hduser', 'nexus', 'ethos', 'Admin', 'mc', 'telnet']

host_indicators = ['mkdir', 'cd', 'vi']

packets = []
ip_packets = []
ip_ports = []
num_of_list = [0, 0, 0, 0, 0]
dst_count = 0
src_count = 0
src_port_count = 0
dst_port_count = 0
decoded_flag = ''

def packet_callback(pkt):
    pkt.show()

def time_keeping(name):
    logging.info("Thread starting %s", name)
    while True:
        current_time = int(datetime.now().timestamp())
        removal_time = current_time - 2
        if packets:
            for i in packets:
                if i[5] < removal_time:
                    print("remove %s", i)
                    packets.remove(i)
        print(packets)
        time.sleep(2)
        print("inside after")
        logging.info("Thread stopped %s", name)

def packet_capture():
    #sniff(filter="ip and host 192.168.86.248 and port 37", iface="enp0s31f6", prn=Decode_Packet, store=0)
    #sniff(filter="ip and host 192.168.86.248 and port 123", iface="wlp2s0", prn=Decode_Packet, store=0)
    #sniff(iface="enp0s31f6", prn=Decode_Packet, store=0)
    sniff(filter="port 80", iface="enp0s31f6", prn=Decode_Packet, store=0)


class Decode_Packet():
    import socket
    
     # Determine Service name using Port Number and Protocol
    def get_flags(self, pcap):
        print("inside get_flags ", pcap[TCP].flags)
        # Get SYN Only
        if pcap[TCP].flags.S and not (pcap[TCP].flags.SA or pcap[TCP].flags.A or pcap[TCP].flags.PA):
            return 'S'

        # Get SYN-ACK
        elif pcap[TCP].flags.SA and not (pcap[TCP].flags.S or pcap[TCP].flags.A):
            return 'SA'

        # Get ACK Only
        elif pcap[TCP].flags.A and not (pcap[TCP].flags.S or pcap[TCP].flags.P):
            return 'A'

        # Get PUSH Only
        elif pcap[TCP].flags.P and not (pcap[TCP].flags.S or pcap[TCP].flags.A):
            return 'P'

        # Get FIN 
        elif pcap[TCP].flags.F and not (pcap[TCP].flags.S or pcap[TCP].flags.P):
            return 'F'

        # Get RST
        elif pcap[TCP].flags.R and not (pcap[TCP].flags.S): # or pcap[TCP].flags.A):
            return 'R'

        # Get PUSH ACK
        elif pcap[TCP].flags.PA and not (pcap[TCP].flags.S): # or pcap[TCP].flags.A):
            return 'PA'

    def decode_flag(self, packet, pcap): 
        print("inside decode")

        previous_count = packet
        
        global decoded_flag
        print("packets %s", packet[6], packet[7], packet[8], packet[9])

        # S0: Connection attempt seen, no reply.
        if packet[6] > 0 and packet[7] == 0 and packet[8] == 0 and packet[9] == 0:
            decoded_flag = 'S0'

        # S1: Connection established, not terminated.
        elif packet[6] >= 0 and packet[7] >= 0 and packet[8] > 0 and packet[9] == 0:
            decoded_flag = 'S1'

        # SF: Normal establishment and termination.
        elif packet[6] > 0 and packet[7] > 0 and packet[8] > 0 and packet[9] > 0:
            decoded_flag = 'SF'

        # REJ: Connection attempt rejected.
        elif packet[6] == 0 and packet[7] == 0 and packet[8] > 0 and packet[9] == 1:
            decoded_flag = 'REJ'

        # S2: Connection established and close attempt by originator seen (but noreply from responder).
        elif packet[0] == pcap[IP].src and packet[1] == pcap[IP].dst and packet[2] == pcap[IP].sport and pcap[IP].dport and (pcap[TCP].flags.F or pcap[TCP].flags.R):
            if packet[6] > 0 and packet[7] > 0 and packet[8] == (previous_count[9] +1) and packet[9] == 0 and packet[11] == 1:
                decoded_flag = 'S2'

        # S3: Connection established and close attempt by responder seen (but noreply from originator).
        elif packet[0] == pcap[IP].src and packet[1] == pcap[IP].dst and packet[2] == pcap[IP].sport and pcap[IP].dport and (pcap[TCP].flags.F or pcap[TCP].flags.R):
            if packet[6] > 0 and packet[7] > 0 and packet[8] > 0 and packet[9] == 0 and packet[11] == 1:
                decoded_flag = 'S3'

        # RSTO: Connection established, originator aborted (sent a RST).
        elif packet[6] == 1 and packet[7] == 1 and packet[8] == 1 and packet[9] == 1:
            if packet[0] == pcap[IP].src and packet[1] == pcap[IP].dst and packet[2] == pcap[IP].sport and pcap[IP].dport and pcap[TCP].flags.R:
                decoded_flag = 'RSTO'

        # RSTR: Established, responder aborted.
        elif packet[6] == 1 and packet[7] == 1 and packet[8] == 1 and packet[9] == 1:
            if packet[0] == pcap[IP].dst and packet[1] == pcap[IP].src and packet[2] == pcap[IP].dport and pcap[IP].sport and pcap[TCP].flags.R:
                decoded_flag = 'RSTR'

        # RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYNACK from the responder.
        elif packet[6] == 1 and packet[7] == 0 and packet[8] == 0 and packet[9] == 1:
            decoded_flag = 'RSTOS0'

        # RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
        elif packet[6] == 0 and packet[7] == 1 and packet[8] == 0 and packet[9] == 1:
            decoded_flag = 'RSTRH'

        # SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
        elif packet[6] == 0 and packet[7] == 1 and packet[8] == 0 and packet[9] == 1:
            decoded_flag = 'SH'

        # SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
        elif packet[6] == 0 and packet[7] == 1 and packet[8] == 0 and packet[11] == 1:
            decoded_flag = 'SHR'

        # OTH: No SYN seen, just midstream traffic (a “partial connection” that wasnot later closed).
        elif packet[6] == 0 and packet[7] > 0 or packet[8] > 0 and packet[9] == 1:
            decoded_flag = 'OTH'

        else:
            decoded_flag = 'NF'

        print("print decoded flag %s", decoded_flag)
        print(packets)
        return decoded_flag

    def add_packet_to_list(self, src_ip, dst_ip, src_port, dst_port, payload_size, pcap, service):
        packet_exists = False
        ip_packet_exists = False
        ip_port_exist = False
        time_added = int(datetime.now().timestamp())
        print("new packets %s", packets)
        # ip_packet list (11)- [src_ip, dst_ip, src_count, dst_count, time_added, S0, S1, S2, S3, REJ, service]
        if ip_packets:
            for i in ip_packets:
                if i[1] == dst_ip:
                    i[3] = i[3] + 1
                if i[0] == src_ip:
                    i[2] = i[2] + 1
                    
                if i[0] == src_ip and i[1] == dst_ip:
                    ip_packet_exists = True
            if not ip_packet_exists:
                ip_packet = [src_ip, dst_ip, 1, 1, time_added, 0, 0, 0, 0, 0, service]
                ip_packets.append(ip_packet)
        else:
            ip_packet = [src_ip, dst_ip, 1, 1, time_added, 0, 0, 0, 0, 0, service]
            ip_packets.append(ip_packet)

        print("IP Packets: ", ip_packets)

        # ip_ports list - [src_port, dst_port, src_port_count, dst_port_count, time_added, S0, S1, S2, S3, REJ, service]
        if ip_ports:
            for i in ip_ports:
                if i[0] == src_port:
                    i[2] = i[2] + 1

                if i[1] == dst_port:
                    i[3] = i[3] + 1

                if i[0] == src_ip and i[1] == dst_port:
                    ip_port_exist = True
            
            if not ip_port_exist:
                ip_port = [src_port, dst_port, 1, 1, time_added, 0, 0, 0, 0, 0, service]
                ip_ports.append(ip_port)
        else:
            ip_port = [src_port, dst_port, 1, 1, time_added, 0, 0, 0, 0, 0, service]
            ip_ports.append(ip_port)

        s, sa, a, rst, pa, f = 0, 0, 0, 0, 0, 0

        if packets:
            # Packet List - [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, syn, syn-ack, ack, rst, pa, f, fa]
            for i in packets:
                if i[0] == src_ip and i[1] == dst_ip and i[2] == src_port and i[3] == dst_port:
                    print("same source\n")
                    print("source %s", i)
                    i[4] = int(i[4]) + int(payload_size)
                    
                    flag = self.get_flags(pcap)
                    print("flag is ", flag)
                    if flag == 'S':
                        print("inside flag is", flag)
                        i[6] += 1
                    elif flag == 'SA':
                        print("inside flag is", flag)
                        i[7] += 1
                    elif flag == 'A':
                        print("inside flag is", flag)
                        i[8] += 1
                        print(i)
                    elif flag == 'RST':
                        print("inside flag is", flag)
                        i[9] += 1
                    elif flag == 'PA':
                        print("inside flag is", flag)
                        i[10] += 1
                    elif flag == 'F':
                        print("inside flag is", flag)
                        i[11] += 1

                    else:
                        pass

                    self.decode_flag(i, pcap)
                    
                    packet_exists = True

            if not packet_exists:    
                print("inside else")
                flag = self.get_flags(pcap)
                print("flag is %s", flag)
                if flag == 'S':
                    print("inside flag is %s", flag)
                    s = 1
                elif flag == 'SA':
                    print("inside flag is %s", flag)
                    sa = 1
                elif flag == 'A':
                    print("inside flag is %s", flag)
                    a = 1
                elif flag == 'RST':
                    print("inside flag is %s", flag)
                    rst = 1
                elif flag == 'PA':
                    print("inside flag is", flag)
                else:
                    pass

                packet = [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, s, sa, a, rst, pa, f]
                self.decode_flag(packet, pcap)
                print("adding %s", packet)
                packets.append(packet)
                #print(packets)
        else:
            print("inside outside else")
            
            flag = self.get_flags(pcap)
            print("flag is %s", flag)
            if flag == 'S':
                print("inside flag is %s", flag)
                s = 1
            elif flag == 'SA':
                print("inside flag is %s", flag)
                sa = 1
            elif flag == 'A':
                print("inside flag is %s", flag)
                a = 1
            elif flag == 'RST':
                print("inside flag is %s", flag)
                rst = 1
            elif flag == 'PA':
                print("inside flag is", flag)
            else:
                pass
            
            packet = [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, s, sa, a, rst, pa, f]
            self.decode_flag(packet, pcap)
            print("adding %s", packet)
            packets.append(packet)

    def service_name(self, pcap):
        if str(pcap.type) == '2054':
            return "ARP"
            #pcap.show()
        elif str(pcap.type) == '2048':
            if os.path.exists('ports.csv'):
                pass
            else:
                url = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
                r = requests.get(url)
                open('ports.csv', 'wb').write(r.content)

            ports = pd.read_csv('ports.csv')

            service = ports.loc[ports['Port Number'] == str(pcap.dport), 'Service Name']
            if service.empty:
                service = ports.loc[ports['Port Number'] == str(pcap.sport), 'Service Name']
            #print("Service is\n")
            service = service.head(1)
            service = service.to_string(index=False,header=False)
            #print(service)
            return service

    def flag(self, pcap):
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

        #flag = pcap['TCP'].flags

        if str(pcap[IP].proto) == '6':
            #pcap.show()
            flag = str(pcap[TCP].flags)
            return flag

        else:
            print("No flag")

    def land(self, pcap):
        src_ip = pcap[IP].src
        dst_ip = pcap[IP].dst
        if str(pcap[IP].proto) == '6':
            src_port = pcap[TCP].sport
            dst_port = pcap[TCP].dport
        elif str(pcap[IP].proto) == '17':
            src_port = pcap[UDP].sport
            dst_port = pcap[UDP].dport
        
        if src_ip == dst_ip:
            if src_port == dst_port:
                return True
            else:
                return False

    def is_host_login(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if pcap[TCP].dport == 21 or pcap[TCP].sport == 21:
                ftp_data = pcap[Raw].load
                if b'USER ' in ftp_data:
                    username = str(ftp_data.split(b'USER ')[1].strip().decode('utf-8'))
                    print(username)
                    if username in user_hot_list:
                        return 1
                    else:
                        return 0      
            else:
                return 0
        else:
            return 0

    def is_guest_login(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if pcap[TCP].dport == 21 or pcap[TCP].sport == 21:
                ftp_data = pcap[Raw].load
                if b'USER ' in ftp_data:
                    username = str(ftp_data.split(b'USER ')[1].strip().decode('utf-8'))
                    print(username)
                    if username == 'guest':
                        return 1
                    else:
                        return 0      
            else:
                return 0
        else:
            return 0

    def is_hot_indicator(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if pcap[TCP].dport == 23 or pcap[TCP].sport == 23:
                telnet_data = pcap[Raw].load
                if any(item in str(telnet_data).lstrip("b'").split() for item in host_indicators):
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def is_root_shell(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if pcap[TCP].dport == 23 or pcap[TCP].sport == 23:
                telnet_data = pcap[Raw].load
                if "#" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def is_su_root(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if pcap[TCP].dport == 23 or pcap[TCP].sport == 23:
                telnet_data = pcap[Raw].load
                if "su root" in str(telnet_data).lstrip("b'"):
                    print("inside su root")
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def num_root(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "#" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def num_file_create(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "touch" or "vi" or ">" or "nano" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def num_shells(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "$" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def num_access_files(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if ".acl" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def num_out_cmds(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "outbound" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def failed_logins(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "Login incorrect" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def success_login(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if "Login successful" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def is_access_control_file(self, pcap):
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            if (pcap[TCP].dport == 23 or pcap[TCP].sport == 23) or (pcap[TCP].dport == 21 or pcap[TCP].sport == 21):
                telnet_data = pcap[Raw].load
                if ".acl" in str(telnet_data).lstrip("b'"):
                    print(str(telnet_data).lstrip("b'"))
                    return 1
                else:
                    return 0   
            else:
                return 0
        else:
            return 0

    def predict_packet(self, decoded_packet_dataset, target_packet):
        url = 'http://127.0.0.1:5000/pred'

        columns = ['duration','protocol_type_icmp','protocol_type_tcp','protocol_type_udp','service_IRC','service_X11','service_Z39_50','service_aol','service_auth', \
            'service_bgp','service_courier','service_csnet_ns','service_ctf','service_daytime','service_discard','service_domain','service_domain_u','service_echo', \
            'service_eco_i','service_ecr_i','service_efs','service_exec','service_finger','service_ftp','service_ftp_data','service_gopher','service_harvest','service_hostnames', \
            'service_http','service_http_2784','service_http_443','service_http_8001','service_imap4','service_iso_tsap','service_klogin','service_kshell','service_ldap', \
            'service_link','service_login','service_mtp','service_name','service_netbios_dgm','service_netbios_ns','service_netbios_ssn','service_netstat','service_nnsp', \
            'service_nntp','service_ntp_u','service_other','service_pm_dump','service_pop_2','service_pop_3','service_printer','service_private','service_red_i','service_remote_job', \
            'service_rje','service_shell','service_smtp','service_sql_net','service_ssh','service_sunrpc','service_supdup','service_systat','service_telnet','service_tftp_u', \
            'service_tim_i','service_time','service_urh_i','service_urp_i','service_uucp','service_uucp_path','service_vmnet','service_whois','flag_OTH','flag_REJ','flag_RSTO', \
            'flag_RSTOS0','flag_RSTR','flag_S0','flag_S1','flag_S2','flag_S3','flag_SF','flag_SH','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins', \
            'logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login', \
            'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate', \
            'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate', \
            'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate', 'difficulty_level'] # 

        print("Columns: ", len(columns))
        print(len(decoded_packet_dataset))
        data = pd.DataFrame([decoded_packet_dataset], columns=columns)
        data = data.drop('difficulty_level',axis=1)
        data = data.astype(float)

        print("Data: ", data)
        data = data.to_dict()

        ip_src = {"ip_src":str(target_packet[0])}
        ip_dst = {"ip_dst":str(target_packet[1])}
        port_src = {"port_src":str(target_packet[2])}
        port_dst = {"port_dst":str(target_packet[3])}

        j_data = json.dumps(data)

        z = json.loads(j_data)

        z.update(ip_src)
        z.update(ip_dst)
        z.update(port_src)
        z.update(port_dst)

        j_data = json.dumps(z)

        print("j data: $$$$$", j_data)

        headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
        r = requests.post(url, data=j_data, headers=headers)

    def __init__(self, pcap):
        decoded_packet = []
        numeric_features = [0] * 39 
        protocol_list = [0] * 3
        service_list = [0] * 70
        flags_list = [0] * 11

        if str(pcap.name) == 'Ethernet':
            try:
                if not (pcap.type):
                    print("No Protocol")
                else:
                    if str(pcap.type) == '2054':
                        decoded_packet.insert(2, 'ARP')
                        print("ARP")

                    elif str(pcap.type) == '2048':

                        # Decode Protocol Type
                        self.protocol = pcap.type
                        #print("Protocol is: " + str(self.protocol))
                        protocol_list_heading = ["protocol_type_icmp","protocol_type_tcp","protocol_type_udp"]

                        if str(pcap[IP].proto) == '6':
                            protocol_list[1] = 1
                            decoded_packet.insert(2, 'TCP')
                            print("f", pcap[TCP].flags)
                            self.add_packet_to_list(str(pcap[IP].src), str(pcap[IP].dst), str(pcap.sport), str(pcap.dport), str(pcap.len), pcap, self.service_name(pcap))
                        elif str(pcap[IP].proto) == '17':
                            protocol_list[2] = 1
                            decoded_packet.insert(2, 'UDP')
                            #self.add_packet_to_list(str(pcap[IP].src), str(pcap[IP].dst), str(pcap.sport), str(pcap.dport))
                        elif str(pcap[IP].proto) == '1':
                            protocol_list[0] = 1
                            decoded_packet.insert(2, 'ICMP')

                        print("Protocol list: ", protocol_list)

                        # 3 Decode the Service Name of the Packet
                        service_name = self.service_name(pcap)
                        service_list_heading = ["service_IRC", "service_X11", "service_z39-50", "service_aol", "service_auth", "service_bgp", "service_courier", "service_csnet-ns", "service_ctf",\
                            "service_daytime","service_discard","service_domain","service_domain_u","service_echo","service_eco_i","service_ecr_i","service_efs","service_exec","service_finger", \
                            "service_ftp","service_ftp-data","service_gopher","service_harvest","service_hostnames","service_http","service_www-dev","service_https","service_vcom-tunnel","service_imap", \
                            "service_iso-tsap","service_klogin","service_kshell","service_ldap","service_link","service_login","service_mtp","service_name","service_netbios-dgm","service_netbios-ns", \
                            "service_netbios-ssn","service_netstat","service_nnsp","service_nntp","service_ntp_u","service_other","service_pm-dump","service_pop2","service_pop3","service_printer", \
                            "service_private","service_red_i","service_netrjs","service_rje","service_shell","service_smtp","service_sql-net","service_ssh","service_sunrpc","service_supdup", \
                            "service_systat","service_telnet","service_tftp_u","service_tim_i","service_time","service_urh_i","service_urp_i","service_uucp","service_uucp-path","service_vmnet", \
                            "service_whois"]

                        service_name = "service_" + service_name

                        if service_name in service_list_heading:
                            print(service_name)
                            service_list[service_list_heading.index(service_name)] = 1

                        else:
                            print("Not found")

                        print("Service list: ", service_list)

                        decoded_packet.insert(3, service_name)

                        # 4 Decode Flag
                        
                        print(str(pcap[IP].proto))
                        if str(pcap[IP].proto) == '6':
                            flag = decoded_flag
                            #flag = self.flag(pcap)
                            decoded_packet.insert(4, flag)
                            # 9 Urgent Flag
                            if flag == '32':
                                decoded_packet.insert(9, '1')
                                numeric_features[3] = 1
                                    
                        elif str(pcap[IP].proto) == '17':
                            pass
                        elif str(pcap[IP].proto) == '1':
                            pass
                        else:
                            print("No flag")

                        numeric_feature_headings = ["duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted", \
                            "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate","rerror_rate", \
                            "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate", \
                            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","difficulty_level"] 
                        
                        # 5 Src Bytes
                        for i in packets:
                            if i[0] == str(pcap[IP].src) and i[1] == str(pcap[IP].dst) and i[2] == str(pcap.sport) and i[3] == str(pcap.dport):
                                decoded_packet.insert(5, i[4])
                                numeric_features[1] = i[4]
                        # 6 6 Dst Bytes
                            if i[0] == str(pcap[IP].dst) and i[1] == str(pcap[IP].src) and i[2] == str(pcap.dport) and i[3] == str(pcap.sport):
                                decoded_packet.insert(6, i[4])
                                numeric_features[2] = i[4]

                        # 7 Is land True or False
                        if self.land(pcap):
                            decoded_packet.insert(7, 1)
                            numeric_features[3] = 1
                        else:
                            decoded_packet.insert(7, 0)
                            numeric_features[3] = 0

                        # 10 hot indicators
                        is_host_indicator = self.is_hot_indicator(pcap)
                        decoded_packet.insert(10, is_host_indicator)
                        numeric_features[6] = is_host_indicator

                        print("decoded packet: ", decoded_packet)

                        # 11 Num of failed logins
                        # ip_packet list (13)- [src_ip, dst_ip, src_count, dst_count, num_failed_logins, num_compromised, num_root_operations, num_file_creation, \
                        # num_shell_prompts, num_of_access_files, num_outbound_cmds]
                        
                        failed_logins = self.failed_logins(pcap)
                        
                        if ip_packets:
                            for i in ip_packets:
                                if (i[0] == pcap[IP].src and i[1] == pcap[IP].dst) or (i[0] == pcap[IP].dst and i[1] == pcap[IP].src):

                                    if failed_logins:
                                        i[4] = i[4] + 1
                                        if len(decoded_packet) == 12:
                                            decoded_packet[11] = i[4]
                                        else:
                                            decoded_packet.insert(11, i[4])

                                    numeric_features[7] = i[4]

                        # 12 Login Status
                        success_login = self.success_login(pcap)
                        decoded_packet.insert(12, success_login)
                        numeric_features[8] = success_login

                        # 14 Root shell is obtained
                        root_shell = self.is_root_shell(pcap)
                        decoded_packet.insert(14, root_shell)
                        numeric_features[10] = root_shell

                        # 15 Su attempted
                        is_su_root = self.is_su_root(pcap)
                        decoded_packet.insert(15, is_su_root)
                        numeric_features[11] = is_su_root

                        # 16 Num Root
                        num_root = self.num_root(pcap)
                        decoded_packet.insert(16, num_root)
                        if num_root:
                            num_of_list[0] = num_of_list[0] + 1
                        numeric_features[12] = num_of_list[0]

                        # 17 Num File Creations
                        num_file_create = self.num_file_create(pcap)
                        decoded_packet.insert(17, num_file_create)
                        if num_file_create:
                            num_of_list[0] = num_of_list[1] + 1
                        numeric_features[13] = num_of_list[1]

                        # 18 Num Shells
                        num_shells = self.num_shells(pcap)
                        decoded_packet.insert(18, is_su_root)
                        if num_shells:       
                            num_of_list[0] = num_of_list[2] + 1
                        numeric_features[14] = num_of_list[2]
                        
                        # 19 Num access files
                        num_access_files = self.num_access_files(pcap)
                        decoded_packet.insert(19, num_access_files)
                        if num_access_files:
                            num_of_list[0] = num_of_list[3] + 1
                        numeric_features[15] = num_of_list[3]

                        # 20 Num Outbount Cmds
                        num_out_cmds = self.num_out_cmds(pcap)
                        decoded_packet.insert(20, num_out_cmds)
                        if num_out_cmds:
                            num_of_list[0] = num_of_list[4] + 1
                        numeric_features[16] = num_of_list[4]

                        # 21 Hot Logins
                        is_host_login = self.is_host_login(pcap)
                        decoded_packet.insert(21, is_host_login)
                        numeric_features[17] = is_host_login

                        # 22 Guest Logins
                        is_guest_login = self.is_guest_login(pcap)
                        decoded_packet.insert(22, is_guest_login)
                        numeric_features[18]= is_guest_login

                        # 13 Num of comprised conditions

                        numeric_features[9] = numeric_features[3] + numeric_features[8]

                        # 23 Dst Count
                        
                        service_dict = {}
                        for i in ip_packets:
                            if i[1] == str(pcap[IP].dst):
                                i[3] = i[3] + 1
                                if len(decoded_packet) == 24:
                                    decoded_packet[23] = i[3]
                                else:
                                    decoded_packet.insert(23, i[3])
                                
                                numeric_features[19] = i[3]

                                if str(pcap[IP].proto) == '6':

                                    if flag == 'S0':
                                        i[5] += 1
                                    elif flag == 'S1':
                                        i[6] += 1
                                    elif flag == 'S2':
                                        i[7] += 1
                                    elif flag == 'S3':
                                        i[8] += 1
                                    elif flag == 'REJ':
                                        i[9] += 1

                                    if i[3] != 0:
                                #26
                                        serror_rate = (i[5] + i[6] + i[7] + i[8]) / i[3]

                                        print("serror: ", serror_rate, i[5], i[6], i[7], i[8], i[3])
                                        numeric_features[21]= "{:.1f}".format(serror_rate)
                                #28
                                        rerror_rate = i[9] / i[3]

                                        numeric_features[23]= "{:.1f}".format(rerror_rate)

                                        print("division *** ", "{:.1f}".format(serror_rate), "{:.1f}".format(rerror_rate))
                                
                                else:
                                    numeric_features[21]= "{:.2f}".format(0.0)
                                    numeric_features[23]= "{:.2f}".format(0.0)
                                
                                #30
                                print("##### 30: ", i[10], service_dict)
                                if i[10] in service_dict.keys():
                                    
                                    for key, value in service_dict.items():
                                        if key == i[10]:
                                            value = value + 1

                                            #if i[3] != 0:

                                            service_dict[i[10]] = value
                                            print("Value ****: ", value, i[3])
                                            value = value / i[3]

                                            numeric_features[25]= "{:.1f}".format(value)
                                            #31
                                            numeric_features[26]= "{:.1f}".format(1 - value)

                                            print("Service Dict: ", service_dict)

                                else:
                                    service_dict.update({i[10] : 1})
                                    print(service_dict)


                        service_port_dict = {}
                        for i in ip_ports:
                            if i[1] == str(pcap.dport):
                                i[3] = i[3] + 1
                                if len(decoded_packet) == 25:
                                    decoded_packet[24] = i[3]
                                else:
                                    decoded_packet.insert(24, i[3])
                                
                                numeric_features[20] = i[3]

                                if str(pcap[IP].proto) == '6':

                                    if flag == 'S0':
                                        i[5] += 1
                                    elif flag == 'S1':
                                        i[6] += 1
                                    elif flag == 'S2':
                                        i[7] += 1
                                    elif flag == 'S3':
                                        i[8] += 1
                                    elif flag == 'REJ':
                                        i[9] += 1

                                    if i[3] != 0:
                                #27
                                        srverror_rate = (i[5] + i[6] + i[7] + i[8]) / i[3]

                                        numeric_features[22]= "{:.1f}".format(srverror_rate)
                                #29
                                        srvrerror_rate = i[9] / i[3]

                                        numeric_features[24]= "{:.1f}".format(srvrerror_rate)

                                        print("division *** ", "{:.1f}".format(srverror_rate), "{:.2f}".format(srvrerror_rate))

                                else:
                                    numeric_features[22]= "{:.2f}".format(0.0)
                                    numeric_features[24]= "{:.2f}".format(0.0) 
                        #[src_ip, dst_ip, src_count, dst_count, time_added, S0, S1, S2, S3, REJ, service]
                        # 24 Dst Port Count
                        
                        for i in ip_ports:
                            if i[1] == str(pcap[IP].dport):
                                i[3] =+ 1
                                if len(decoded_packet) == 25:
                                    decoded_packet[24] = i[3]
                                else:
                                    decoded_packet.insert(24, i[3])

                                numeric_features[20] = i[3]
                        
                        # 25 Serror Rate
                        

                        # 33 Src Count (Number of connections having the same destination host IP address)
                        
                        for i in ip_packets:
                            if i[0] == str(pcap[IP].src):
                                i[2] = i[2] + 1
                                if len(decoded_packet) == 33:
                                    decoded_packet[32] = i[2]
                                else:
                                    decoded_packet.insert(32, i[2])

                                numeric_features[28] = i[2]
                        
                        # 34 Src Port Count (Number of connections having the same port number)
                        
                        for i in ip_ports:
                            if i[0] == str(pcap[IP].sport):
                                i[2] = i[2] + 1
                                if len(decoded_packet) == 34:
                                    decoded_packet[33] = i[2]
                                else:
                                    decoded_packet.insert(33, i[2])

                                numeric_features[29] = i[2]
                        
                        # 34 Percentage of connections that were to the same service among the connections aggregated in dst host count (#32)
                        # ip_packet list (11)- [src_ip, dst_ip, src_count, dst_count, time_added, S0, S1, S2, S3, REJ, service]
                        service_dst_dict = {}
                        for i in ip_packets:
                            #39 Number of connection with same dst address
                            if i[0] == str(pcap[IP].src):
                                i[2] = i[2] + 1
                                if len(decoded_packet) == 24:
                                    decoded_packet[23] = i[3]
                                else:
                                    decoded_packet.insert(23, i[3])
                                
                                numeric_features[28] = i[2]

                                if str(pcap[IP].proto) == '6':

                                    if flag == 'S0':
                                        i[5] += 1
                                    elif flag == 'S1':
                                        i[6] += 1
                                    elif flag == 'S2':
                                        i[7] += 1
                                    elif flag == 'S3':
                                        i[8] += 1
                                    elif flag == 'REJ':
                                        i[9] += 1

                                    if i[2] != 0:
                                #39
                                        serror_rate = (i[5] + i[6] + i[7] + i[8]) / i[2] / 10

                                        numeric_features[34]= "{:.2f}".format(serror_rate)
                                #40
                                        rerror_rate = i[9] / i[2]

                                        numeric_features[36]= "{:.2f}".format(rerror_rate)

                                        print("division *** ", "{:.2f}".format(serror_rate), "{:.2f}".format(rerror_rate))
                                
                                else:
                                    numeric_features[34]= "{:.2f}".format(0.0)
                                    numeric_features[36]= "{:.2f}".format(0.0)

                                print("##### 34: ", i[10], service_dst_dict)
                                if i[10] in service_dst_dict.keys():
                                    
                                    for key, value in service_dst_dict.items():
                                        if key == i[10]:
                                            value = value + 1

                                            #if i[3] != 0:

                                            service_dict[i[10]] = value
                                            print("Value ****: ", value, i[2])
                                            value = value / i[2]

                                            numeric_features[30]= "{:.1f}".format(value)
                                            #35
                                            numeric_features[31]= "{:.1f}".format(1 - value)

                                            print("Service Dict: ", service_dst_dict)

                                else:
                                    service_dst_dict.update({i[10] : 1})
                                    print(service_dst_dict)
                        # 40
                        service_dict = {}
                        for i in ip_ports:
                            if i[1] == str(pcap.dport):
                                i[3] =+ 1
                                if len(decoded_packet) == 24:
                                    decoded_packet[23] = i[3]
                                else:
                                    decoded_packet.insert(23, i[3])
                                
                                numeric_features[29] = i[3] * 10

                                if str(pcap[IP].proto) == '6':

                                    if flag == 'S0':
                                        i[5] += 1
                                    elif flag == 'S1':
                                        i[6] += 1
                                    elif flag == 'S2':
                                        i[7] += 1
                                    elif flag == 'S3':
                                        i[8] += 1
                                    elif flag == 'REJ':
                                        i[9] += 1

                                    #if i[2] != 0:
                                #27
                                    srverror_rate = (i[5] + i[6] + i[7] + i[8]) / i[2] / 10

                                    numeric_features[35]= "{:.2f}".format(serror_rate)
                                #29
                                    rerror_rate = i[9] / i[2]

                                    numeric_features[37]= "{:.2f}".format(rerror_rate)

                                    print("division *** ", "{:.2f}".format(serror_rate), "{:.2f}".format(rerror_rate))

                                #else:
                                #    numeric_features[35]= "{:.2f}".format(0.0)
                                #    numeric_features[37]= "{:.2f}".format(0.0)
                    
                    else:
                        print("in else")
                        pass
                
                    
                    print("------------------------")
                    print(decoded_packet)
                    print("------------------------")

                    # Load the training set scalar
                    scaler = load(open('scaler.pkl', 'rb'))

                    scaler.clip = False

                    print("Numeric 1: ", numeric_features)

                    pd.set_option("display.max_rows", None, "display.max_columns", None)

                    numeric_features = pd.DataFrame([numeric_features])
                    numeric_features = numeric_features.astype(float)

                    # Scale the data as per the training set
                    numeric_features = scaler.transform(numeric_features)

                    print("numeric features: ",numeric_features.shape)

                    numeric_features = numeric_features.tolist()
                    print("Numeric 2: ", numeric_features)

                    numeric_features[0][7] = 0.0

                    #decoded_packet_dataset = protocol_list + service_list + flags_list

                    #decoded_packet_dataset = pd.DataFrame([decoded_packet_dataset])
                    # SF flag
                    #flags_list[9] = 1
                    # S1 flag
                    #flags_list[6] = 1

                    print("flag list: ", flags_list)

                    print("length: ", len(protocol_list), len(service_list), len(flags_list), len(numeric_features[0]))
                    decoded_packet_dataset = protocol_list + service_list + flags_list

                    duration = numeric_features[0][0]
                    del numeric_features[0][0]
                    #duration = pd.DataFrame(numeric_features['duration'])
                    #decoded_packet_dataset = decoded_packet_dataset.join(numeric_features.drop(['duration']))

                    #print("decoded_packet_dataset", decoded_packet_dataset)

                    decoded_packet_dataset = decoded_packet_dataset + numeric_features[0]

                    #print("duration: " + str(duration))
                    decoded_packet_dataset = [duration] + decoded_packet_dataset

                    #decoded_packet_dataset[113] = 1.0
                    #decoded_packet_dataset[114] = 1.0
                    #decoded_packet_dataset[122] = 1.0

                    #S1 flag 
                    #decoded_packet_dataset[80] = 0.0

                    #SF flag
                    decoded_packet_dataset[83] = 1.0
                    decoded_packet_dataset[105] = 0.0
                    decoded_packet_dataset[106] = 0.0

                    # land attack
                    decoded_packet_dataset[87] = 0.0


                    #decoded_packet_dataset[113] = 1.0
                    '''
                    decoded_packet_dataset[114] = 1.0
                    decoded_packet_dataset[116] = 0.25
                    # dst_host_serror_rate
                    decoded_packet_dataset[117] = 0.2

                    decoded_packet_dataset[118] = 0.0
                    decoded_packet_dataset[119] = 0.0
                    '''
                    print(decoded_packet_dataset)
                    print(len(decoded_packet_dataset))

                    target_packet = [pcap[IP].src, pcap[IP].dst, pcap.sport, pcap.dport]

                    decoded_packet_dataset = decoded_packet_dataset
                    print(decoded_packet_dataset)
                    predict_packet = self.predict_packet(decoded_packet_dataset, target_packet)

                    #print(numeric_features)
                    
                #else:
                #    print("in else")
            except Scapy_Exception:
                try:
                    print("exception")
                except Exception:
                    pass
                raise Scapy_Exception("Not a supported capture file")

                

def ftp_test(pcap):
    if pcap.haslayer(TCP) and pcap.haslayer(Raw):
        if pcap[TCP].dport == 21 or pcap[TCP].sport == 21:
            pcap.show()
        else:
            pass
    else:
        pass

if __name__ == '__main__':

# thread

    y = threading.Thread(target=packet_capture)
    y.start()

    logging.info("starting thread")
    x = threading.Thread(target=time_keeping, args=(1,))
    x.start()