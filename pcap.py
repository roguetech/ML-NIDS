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

decoded_packet = []
packets = []
ip_packets = []
ip_ports = []
dst_count = 0
src_count = 0
src_port_count = 0
dst_port_count = 0

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
    sniff(filter="ip and host 192.168.86.248 and port 1234", iface="enp0s31f6", prn=Decode_Packet, store=0)
    #sniff(filter="ip and host 192.168.86.248 and port 123", iface="wlp2s0", prn=Decode_Packet, store=0)


class Decode_Packet():
    import socket
     # Determine Service name using Port Number and Protocol

    def get_flags(self, pcap):
        # Get SYN Only
        if pcap[TCP].flags.S and not (pcap[TCP].flags.A or pcap[TCP].flags.P):
            return 'S'

        # Get SYN-ACK
        if pcap[TCP].flags.S and pcap[TCP].flags.A and not (pcap[TCP].flags.P):
            return 'SA'

        # Get ACK Only
        if pcap[TCP].flags.A and not (pcap[TCP].flags.S or pcap[TCP].flags.P):
            return 'A'

        # Get RST
        if pcap[TCP].flags.R and not (pcap[TCP].flags.S or pcap[TCP].flags.A):
            return 'R'

    def decode_flag(self): 
        # S0: Connection attempt seen, no reply.
        if packet[6] > 0 and packet[7] == 0 and packet[8] == 0 and packet[9] == 0:
            decoded_packet.insert(4, 'S0')

        # S1: Connection established, not terminated.
        if packet[6] > 0 and packet[7] > 0 and packet[8] > 0 and packet[9] == 0:
            decoded_packet.insert(4, 'S1')

        # SF: Normal establishment and termination.
        if packet[6] > 0 and packet[7] > 0 and packet[8] > 0 and packet[9] > 0:
            decoded_packet.insert(4, 'SF')

        # REJ: Connection attempt rejected.
        if packet[6] == 1 and packet[7] > 0 and packet[8] > 0 and packet[9] == 1:
            decoded_packet.insert(4, 'REJ')

        # S2: Connection established and close attempt by originator seen (but noreply from responder).

        # S3: Connection established and close attempt by responder seen (but noreply from originator).

        # RSTO: Connection established, originator aborted (sent a RST).

        # RSTR: Established, responder aborted.

        # RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYNACK from the responder.

        # RSTRH: Responder sent a SYN ACK followed by a RST, we never saw aSYN from the (purported) originator.

        # SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACKfrom the responder (hence the connection was “half” open).

        # SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYNfrom the originator.

        # OTH: No SYN seen, just midstream traffic (a “partial connection” that wasnot later closed).
        if packet[6] == 0 and packet[7] > 0 and packet[8] > 0 and packet[9] > 1:
            decoded_packet.insert(4, 'OTH')

    def add_packet_to_list(self, src_ip, dst_ip, src_port, dst_port, payload_size, pcap):
        packet_exists = False
        ip_packet_exists = False
        ip_port_exist = False
        time_added = int(datetime.now().timestamp())
        print(packets)
        # ip_packet list - [src_ip, dst_ip, src_count, dst_count]
        if ip_packets:
            for i in ip_packets:
                if i[1] == dst_ip:
                    global dst_count
                    dst_count += 1
                    i[3] = dst_count 
                    print("dst_count: %s", dst_count)
                    print(ip_packets)
                if i[0] == src_ip:
                    global src_count
                    src_count += 1
                    i[2] = dst_count
                    
                if i[0] == src_ip and i[1] == dst_ip:
                    ip_packet_exists = True
            if not ip_packet_exists:
                ip_packet = [src_ip, dst_ip, 0, 0]
                ip_packets.append(ip_packet)
        else:
            ip_packet = [src_ip, dst_ip, 0, 0]
            ip_packets.append(ip_packet)

        # ip_ports list - [src_port, dst_port, src_port_count, dst_port_count]
        if ip_ports:
            for i in ip_ports:
                if i[0] == src_port:
                    global src_port_count
                    src_port_count += 1

                if i[1] == dst_port:
                    global dst_port_count
                    dst_port_count += 1

                if i[0] == src_ip and i[1] == dst_port:
                    ip_port_exist = True
            
            if not ip_port_exist:
                ip_port = [src_port, dst_port, 0, 0]
                ip_ports.append(ip_port)
        else:
            ip_port = [src_port, dst_port, 0, 0]
            ip_ports.append(ip_port)

        s, sa, a, rst = 0, 0, 0, 0
        if packets:
            # Packet List - [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, syn, syn-ack, ack, rst]
            for i in packets:
                if i[0] == src_ip and i[1] == dst_ip and i[2] == src_port and i[3] == dst_port:
                    print("same source\n")
                    print("source %s", i)
                    i[4] = int(i[4]) + int(payload_size)
                    flag = self.get_flags(pcap)
                    print("flag is %s", flag)
                    if flag == 'S':
                        print("inside flag is %s", flag)
                        i[6] += 1
                    elif flag == 'SA':
                        print("inside flag is %s", flag)
                        i[7] += 1
                    elif flag == 'A':
                        print("inside flag is %s", flag)
                        i[8] += 1
                        print(i)
                    elif flag == 'RST':
                        print("inside flag is %s", flag)
                        i[9] += 1
                    else:
                        pass

                    self.decode_flag()

                    packet_exists = True
                #elif i[0] == dst_ip and i[1] == src_ip and i[2] == dst_port and i[3] == src_port:
                #    print("same dst")
                #    print("dst: %s", i)
                #    print(dst_ip)
                #else:
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
                else:
                    pass

                self.decode_flag()

                packet = [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, s, sa, a, rst]
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
            else:
                pass

            self.decode_flag()

            packet = [src_ip, dst_ip, src_port, dst_port, payload_size, time_added, s, sa, a]
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

    def __init__(self, pcap):
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
                        if str(pcap[IP].proto) == '6':
                            decoded_packet.insert(2, 'TCP')
                            self.add_packet_to_list(str(pcap[IP].src), str(pcap[IP].dst), str(pcap.sport), str(pcap.dport), str(pcap.len), pcap)
                        elif str(pcap[IP].proto) == '17':
                            decoded_packet.insert(2, 'UDP')
                            #self.add_packet_to_list(str(pcap[IP].src), str(pcap[IP].dst), str(pcap.sport), str(pcap.dport))
                        elif str(pcap[IP].proto) == '1':
                            decoded_packet.insert(2, 'ICMP')

                        # 3 Decode the Service Name of the Packet
                        service_name = self.service_name(pcap)
                        decoded_packet.insert(3, service_name)

                        # 4 Decode Flag
                        '''
                        print(str(pcap[IP].proto))
                        if str(pcap[IP].proto) == '6':
                            flag = self.flag(pcap)
                            decoded_packet.insert(4, flag)
                            # 9 Urgent Flag
                            if flag == '32':
                                decoded_packet.insert(9, '1')
                                # **** TO DO **** count number of urg in a connection
                            
                        elif str(pcap[IP].proto) == '17':
                            pass
                        elif str(pcap[IP].proto) == '1':
                            pass
                        else:
                            print("No flag")
                            #pcap.show()
                            #print(len(pcap[TCP].payload))
                        '''
                        # 5 Src Bytes
                        for i in packets:
                            if i[0] == str(pcap[IP].src) and i[1] == str(pcap[IP].dst) and i[2] == str(pcap.sport) and i[3] == str(pcap.dport):
                                decoded_packet.insert(5, i[4])
                        # 6 6 Dst Bytes
                            if i[0] == str(pcap[IP].dst) and i[1] == str(pcap[IP].src) and i[2] == str(pcap.dport) and i[3] == str(pcap.sport):
                                decoded_packet.insert(6, i[4])
                
                        # 7 Is land True or False
                        if self.land(pcap):
                            decoded_packet.insert(7, 1)
                        else:
                            decoded_packet.insert(7, 0)

                        # 8 Wrong Fragment

                        # 10 hot indicators
                        is_host_indicator = self.is_hot_indicator(pcap)
                        decoded_packet.insert(10, is_host_indicator)

                        # 11 num of failed logins


                        # 15 Su attempted
                        is_su_root = self.is_su_root(pcap)
                        decoded_packet.insert(15, is_su_root)

                        # 21 Hot Logins
                        is_host_login = self.is_host_login(pcap)
                        decoded_packet.insert(21, is_host_login)

                        # 22 Guest Logins
                        is_guest_login = self.is_guest_login(pcap)
                        decoded_packet.insert(22, is_guest_login)

                        # 23 Dst Count
                        for i in ip_packets:
                            if i[1] == str(pcap[IP].dst):
                                decoded_packet.insert(23, i[3])

                        # 24 Dst Port Count
                        for i in ip_ports:
                            if i[1] == str(pcap[IP].dport):
                                decoded_packet.insert(24, i[3])

                        # 25 

                        # 32 Src Count (Number of connections having the same destination host IP address)
                        for i in ip_packets:
                            if i[0] == str(pcap[IP].src):
                                decoded_packet.insert(32, i[2])

                        # 33 Src Port Count (Number of connections having the same port number)
                        for i in ip_ports:
                            if i[0] == str(pcap[IP].sport):
                                decoded_packet.insert(33, i[2])

                    else:
                        print("in else")
                        pass
                
                    
                    print("------------------------")
                    print(decoded_packet)
                    print("------------------------")
                    
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
    #x.start()

#pcap = sniff(count=num_of_packets_to_sniff) 
#    num_of_packets_to_sniff = 5
#sniff(iface="enp0s31f6", prn=Decode_Packet, store=0, count=num_of_packets_to_sniff)
#sniff(iface="enp0s31f6", prn=Decode_Packet, store=0)
#    sniff(iface="enp0s31f6", prn=Decode_Packet, store=0)
#sniff(iface="wlp2s0", prn=Decode_Packet, store=0, count=num_of_packets_to_sniff)
#sniff(iface="lo", prn=ftp_test, store=0)
#sniff(iface = "enp0s31f6",prn=lambda x:x.summary())

# rdpcap returns packet list
## packetlist object can be enumerated 
#print(type(pcap))
#print(len(pcap))
#print(pcap)
#print(pcap[0])

# We're only interested in Layers 3 (IP) and 4 (TCP AND UDP) 
## We'll parse those two layers and the layer 4 payload
## When capturing we capture layer 2 frames and beyond

# Retrieving a single item from packet list
'''
ethernet_frame = pcap[1]
ip_packet = ethernet_frame.payload
segment = ip_packet.payload
data = segment.payload # Retrieve payload that comes after layer 4
'''
#for i in len(pcap):
'''
print('##### Ethernet Frame #####\n')
print(ethernet_frame.summary())

print('\n##### IP Packet #####\n')
print(ip_packet.show())

print('\n##### Segment #####\n')
print(segment.summary())

print('\n##### Data #####\n')
print(data.summary())
'''

# Observe that we just popped off previous layer header
#print(ethernet_frame.summary())
#print(ip_packet.summary())
#print(segment.summary())
#print(data.summary()) # If blank, empty object

# Complete depiction of paket
## Achieving understanding that these are the fields will enable the ability 
## to ask the data more meaningful questions ie) type of layer 4 segment is defined in layer 3 packet
#ethernet_frame.show()



#print(type(pcap))
#print(pcap[50].dport)
#print(pcap[50].proto)
'''
for i in len(pcap):
    #i = 5
    service = service_name(pcap[i].sport, pcap[i].dport, pcap[i].proto)
    print(service)
'''