import pandas as pd
from scapy.packet import Padding
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import os
import re
import matplotlib.pyplot as plt


def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload

    return packet
def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

    return packet

def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet

    return packet



dir_path = r"D:\Ammar\VPN Stream\VPN-PCAPs\\"
# out_pathT = 'D:\\New Research\\3 - VPN vs Non-VPN Paper\\Figure\\Traffic\\'
out_path = 'D:\\Ammar\\VPN Stream\\Result\\FlowPic\\'


os.chdir(dir_path)
dirlist = os.listdir(dir_path)
for dirName in dirlist:
    count = 0
    print(dirName)
    ImgName = dirName
    dirName = dir_path + dirName
    os.chdir(dirName)
    fileList = os.listdir(dirName)
    for file in fileList:
        print(file)
        Allpackets=rdpcap(file)
 
        packet_info = pd.DataFrame()
        packet_length = []
        packet_time = []
        
        for packet in Allpackets:
            packet=remove_ether_header(packet)
            packet=mask_ip(packet)
            packet=pad_udp(packet)
            
            packet_length.append(len(packet))
            packet_time.append(packet.time)
        
        
        packet_info = packet_info.append(pd.DataFrame({'Packet_Length':packet_length,'Packet_Arrival':packet_time})) 
        
        packet_info['Packet_Arrival'] = (packet_info['Packet_Arrival']-min(packet_info['Packet_Arrival']))/(max(packet_info['Packet_Arrival'])-min(packet_info['Packet_Arrival']))
        
        packet_info['Packet_Arrival'] = packet_info['Packet_Arrival'] * 120
        plt.ylim(ymax = 1500, ymin=0)
        #plt.xlim(xmax = 1400, xmin=0)
        plt.scatter(packet_info['Packet_Arrival'], packet_info['Packet_Length'], color= "black", marker= "s", s=30)
        filename = out_path + ImgName +'_'+str(count)+'.png'
        # filenameT = out_pathT+traffic_label+'_'+str(count)+'.png'
        plt.savefig(filename,dpi=600)
        # plt.savefig(filenameT,dpi=600)
        count = count + 1
        plt.clf()
