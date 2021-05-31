from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
import requests
import os
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

def packet_callback(pkt):
    pkt.show()

class Decode_Packet():
    import socket
     # Determine Service name using Port Number and Protocol
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
            print("Service is\n")
            print(service.head(1))
            return service
            '''
            try:
                if 1 <= int(pcap.dport) <= 1024:
                    service = socket.getservbyport(pcap.dport, 'tcp')
                    return service
                elif 1 <= int(pcap.sport) <= 1024:
                    service = socket.getservbyport(pcap.sport, 'tcp')
                    return service
                else:
                    print(pcap.sport)
                    print(pcap.dport)
                print("-------------------------------------")
            except:
                print("Error")
                #pcap.show()
            '''

    def flag(self, pcap):
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

        if pcap[TCP]:
            print(pcap[TCP].flags)

    def __init__(self, pcap):
        self.protocol = pcap.type
        print("Protocol is: " + str(self.protocol))
        self.service_name = self.service_name(pcap)
        #print(self.service_name)
        #if str(pcap.type) == '2048':
        #    self.flag(pcap)
        #F = pcap[IP].flags
        #print(F)
        self.flag = ''
        



#pcap = sniff(count=num_of_packets_to_sniff) 
num_of_packets_to_sniff = 5
sniff(iface="wlp2s0", prn=Decode_Packet, store=0, count=num_of_packets_to_sniff)

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