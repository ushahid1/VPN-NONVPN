import subprocess
import pandas as pd
import os
import csv


def read_pcap(filename, fields=[], display_filter="", timeseries=False, strict=False):
    if timeseries:
        fields = ["frame.time_epoch"] + fields
    fieldspec = " ".join("-e %s" % f for f in fields)
    display_filters = fields if strict else []
    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-R '%s'" % " and ".join(f for f in display_filters)
    options = "-r %s -2 -T fields -Eheader=y" % filename
    cmd = "tshark %s %s" % (options, fieldspec)
    proc = subprocess.Popen(cmd, shell = True,stdout=subprocess.PIPE)
    df = pd.read_table(proc.stdout)
    return df

def _replaceitem(x):
    if x < 4:
        return 0
    
    else:
        return x



           
dir_path= r"D:\Ammar\0 - Dataset (PCAPs)\Videos\Gap Dataset PCAPs\1080p\BPS-LiveTesting\\"
os.chdir(dir_path)
with open(r"D:\Ammar\0 - Dataset (PCAPs)\Videos\Gap Dataset PCAPs\1080p\BPS-LiveTesting_1080.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
           
        dir_path= r"D:\Ammar\0 - Dataset (PCAPs)\Videos\Gap Dataset PCAPs\1080p\BPS-LiveTesting\\"
        fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
        main_dir = os.listdir(dir_path)
        for internal_dir in main_dir: 
          
            if os.path.isdir(dir_path +"\\"+internal_dir):
               
                filelist=os.listdir(dir_path +"\\"+internal_dir )
                
                for file in filelist:
                    filepath=dir_path +internal_dir
                    os.chdir(filepath)
                    print(file)
                    temp=read_pcap(file, fields, timeseries=True, strict=True)
                    temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
                    try: 
                        source_address=temp[temp["ip.dst"] == "192.168.1.192"]
                        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
                    except:
                        source_address=temp[temp["ip.dst"] == "192.168.10.60"]
                        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
                        
                    BPS_list=bytes_per_second['frame.len'][0:120]
                    
                    BPS_list = list(map(_replaceitem, BPS_list))
                    lenBPS = len(BPS_list)
                    if lenBPS < 120:
                        print("len is less")
                        diff = 120- lenBPS
                        for d in range(diff):
                            BPS_list.append(0)
                    BPS_list.append(internal_dir)
                    BPS_list.append(file)
                    writer.writerow(BPS_list)
     