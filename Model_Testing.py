import pandas as pd
import csv
from csv import DictWriter
from selenium import webdriver
import time
from datetime import datetime
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess
import os.path
import numpy as np
from keras.models import load_model


#detect links from model


currentdate = datetime.today().strftime('%d-%m-%Y-%H-%M')

def norm(x,v):
  return x/v
def tostring1(x):
  return '{:.2f}'.format(x)


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

import os

def clickOnAd(driver):
    try:
        res = driver.find_element_by_xpath("//*[contains(text(),'Skip Ad')]").click()        
    except:
        print("didn't find ad video ad insertion")
#The function receive a string indicate the requested video quality



   
def harvest_video(amount,name,url,duration):
    global count
    count = 0
    for x in range(0, amount):
        print('{} run number:{}'.format(name,x))
        downloadVideo("Auto",name,url,duration,x)
    field_names = ['LinkName','Correct']
    dict={'LinkName':name,'Correct':count}
     
   
    with open('D:/Ammar/2-VPNvsNonVPN/Result/BPS-new/ResultsAll_'+currentdate+'.csv', 'a') as f_object:
        dictwriter_object = DictWriter(f_object, fieldnames=field_names)
        dictwriter_object.writerow(dict)
        f_object.close()

def downloadVideo(video_quality,video_name, url, duration_of_the_video,runn):
    global csv_path
    t_time = time.strftime("%H_%M_%S")
    #funcInFile = "Test"
   
    root_path = r"D:\Ammar\2-VPNvsNonVPN\PCAPs\NonVPN-PCAPs(New)_"+currentdate+"\\"
   
    if not os.path.exists(root_path):
        os.makedirs(root_path)
   
    video_path = root_path + video_name +"\\"
    if not os.path.exists(video_path):
        os.makedirs(video_path)

    quality_path =  video_path + "\\"
    if not os.path.exists(quality_path):
        os.makedirs(quality_path)

    filename = quality_path + video_name + "_"  + t_time + ".pcap"
    tsharkOut  = open(filename, "wb")
    tsharkCall = ["C:\\Program Files\\Wireshark\\tshark.exe","-F", "pcap", "-f", "port 443", "-i", "Ethernet 2", "-w", filename] #port 56847 and 51820
   
    tsharkProc = ""
    chrome_options = webdriver.ChromeOptions()

    chrome_options.binary_location ="C:\Program Files\Google\Chrome\Application\chrome.exe"
    chrome_options.add_extension('adblock.crx')
   

    #chrome_options.add_extension('Ultrasurf.crx')
   
    driver = webdriver.Chrome(executable_path='chromedriver.exe',options=chrome_options)

    wait = WebDriverWait(driver, 20)
    driver.get(url)
   
    start_time = time.time()
   
    main_window = driver.current_window_handle
   
    #driver.find_element_by_tag_name('body').send_keys(Keys.CONTROL + 'w')
    driver.switch_to.window(main_window)
    tsharkProc = subprocess.Popen(tsharkCall, stdout=tsharkOut, executable="C:\\Program Files\\Wireshark\\tshark.exe")        
   
    timersetting = False
   
   
    try:
        time.sleep(10)
        clickOnAd(driver)
        time.sleep(10)
        clickOnAd(driver)
        
        wait.until(EC.element_to_be_clickable((By.XPATH, "//button[@aria-label='Play']"))).click()
        
        end_time = time.time()
    except:
        timersetting = True
        end_time = time.time()

    time_elapsed = (end_time - start_time)
   
    if(timersetting):
        duration_of_the_video = duration_of_the_video - time_elapsed
       
   
    time.sleep(duration_of_the_video)
    driver.quit()
    tsharkProc.terminate()
    

    BPS_list=[]
    #orginal CSV path to be replaced here 
    csv_path=r"D:\Ammar\2-VPNvsNonVPN\Result\BPS-new\BPS-NonVPN-iteration.csv"
    with open(csv_path, "a", newline="") as csv_file:
            writer = csv.writer(csv_file)
             
            #dir_path=  r"D:\Ammar\2-VPNvsNonVPN\PCAPs\NonVPN-PCAPs(New)_"+currentdate
            fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
                           
            file = filename
            temp=read_pcap(file, fields, timeseries=True, strict=True)
            temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
            source_address=temp[temp["ip.dst"] == "192.168.10.101"]
            bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
            BPS_list=bytes_per_second['frame.len'][0:120]
           
            BPS_list = list(map(_replaceitem, BPS_list))
            lenBPS = len(BPS_list)
            if lenBPS < 120:
                print("len is less")
                diff = 120- lenBPS
                for d in range(diff):
                    BPS_list.append(0)
            BPS_list.append(video_name)
            writer.writerow(BPS_list)
           
    model_path=r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_23-11-2021_8481447.h5"       
    model = load_model(model_path)
    l_temp=pd.read_pickle(r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_23-11-2021_8481447.pkl")
    array = BPS_list[0:120]
    x = []
    df =  pd.DataFrame (array, columns = ['column_name'])
    df['column_name'] = df['column_name'].astype(int)
    #name = str(df[i,121:].values.tolist())
    x = df['column_name'] #
   
    #v=8481447#change this
    v=int(model_path.split("_")[-1].split(".")[0])
    
    
    
    x1=np.vectorize(norm)(x,v)
   
    labels = np.asarray(l_temp, dtype = np.int8)
    x3 = x1.reshape(1,120,1)
    y_pred1 = model.predict(x3)
   
    l_temp.loc[-1]=y_pred1[0]
   
    predict_name = l_temp.loc[-1].idxmax()
    print("Video name was ",video_name,". The predicted link is: ",predict_name)
   
    if(video_name == predict_name):
        global count
        count += 1
    field_names = ['LinkName','run','prob']
    lis=[]
    for i in range(43):
        lis.append((l_temp.loc[-1].index[i],'{0:.50f}'.format(l_temp.loc[-1][i])))  
    # Dictionary
    dict={'LinkName':video_name,'run':runn,'prob':lis}
     
   
    with open(r'D:\Ammar\2-VPNvsNonVPN\Result\BPS-new\Detailed_Results_'+currentdate+'.csv', 'a') as f_object:        
        dictwriter_object = DictWriter(f_object, fieldnames=field_names)
     
        #Pass the dictionary as an argument to the Writerow()
        dictwriter_object.writerow(dict)
     
        #Close the file object
        f_object.close()
   

       
data = pd.read_csv(r"D:\Ammar\2-VPNvsNonVPN\Code\links.csv")

i=0
while i < len(data['id']):
   
    filename = str(data['id'][i])
    urlF = str(data['Links'][i])
    amount = int(data['numbers'][i])
    link100_url = urlF
    link100_duration = 120
    harvest_video(amount,filename,link100_url,link100_duration)
    i+=1
