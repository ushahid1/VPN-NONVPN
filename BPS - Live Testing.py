# -*- coding: utf-8 -*-
"""
Created on Wed Nov 24 09:53:55 2021

@author: shouz
"""
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
           
    model_path=r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_29-11-2021-16-45_9830494.h5"       
    model = load_model(model_path)
    l_temp=pd.read_pickle(r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_29-11-2021-16-45_9830494.pkl")
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


#model training code
import pandas as pd
from keras.models import Sequential
from keras.layers import Dense
from sklearn.model_selection import train_test_split
from keras.layers import Dropout,Flatten
from sklearn.metrics import classification_report, confusion_matrix,ConfusionMatrixDisplay
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D
from keras.utils.vis_utils import plot_model
from tensorflow import keras as kf
from datetime import datetime
import shutil

dateforupdate = datetime.today().strftime('%d-%m-%Y-%H-%M')
udpatefilename = r"D:/Ammar/2-VPNvsNonVPN/Result/BPS-NonVPN(updated).csv"
copyfname = r"D:/Ammar/2-VPNvsNonVPN/Result/BPS-NonVPN_"+dateforupdate+".csv"

shutil.copy2(udpatefilename,copyfname)

with open(csv_path,'r') as f1:
    new_csv = f1.read()
    f1.close()
    
    
with open(udpatefilename,'a', newline="") as f2:
    f2.write('\n')
    f2.write(new_csv)
    f2.close()


os.remove(csv_path)
#path of csv
data=pd.read_csv(udpatefilename)

x=data.iloc[:,:120]
y=data["Class"]
v=max(np.max(x))
print (v)

#writing max value to file
# =============================================================================
# f = open("/content/drive/My Drive/Colab Notebooks/BPS Dataset/Non-VPN/Max"+date+".txt", "w")
# f.write(str(v))
# f.close()
# =============================================================================


x1=np.vectorize(norm)(x,v) #normalization

import pickle
y=data["Class"]
l_temp=pd.get_dummies(y)
l_temp.to_pickle(r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_"+str(currentdate)+"_"+str(v)+".pkl")
labels = np.asarray(l_temp, dtype = np.int8)
X_train, X_test, y_train, y_test = train_test_split( x1, labels, test_size=0.4, random_state=44)

class TestCallback(kf.callbacks.Callback):
  def __init__(self, test_data):
    self.test_data = test_data
  def on_epoch_end(self, epoch, logs={}):
    x, y = self.test_data
    loss, acc = self.model.evaluate(x, y, verbose=0)
    print('\nTesting loss: {}, acc: {}\n'.format(loss, acc))

input_height=1
input_width=120
num_channels=1
input_shape = (input_height, input_width, num_channels)

X_train = X_train.reshape(X_train.shape[0],X_train.shape[1],1)
X_test = X_test.reshape(X_test.shape[0],X_test.shape[1],1)

sequence_length=120

model = Sequential()

model.add(Conv1D(filters=1024, kernel_size=6, padding='same', activation='relu',input_shape=(sequence_length,1)))
model.add(MaxPooling1D(pool_size=2))
model.add(Conv1D(filters=512, kernel_size=4, padding='same', activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(Conv1D(filters=512, kernel_size=5, padding='same', activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(Dropout(0.2))

model.add(Flatten())
model.add(Dense(43, activation='softmax'))

model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

print(model.summary())
plot_model(model, to_file='model_plot.png', show_shapes=True, show_layer_names=True)

model.fit(X_train, y_train, epochs=100, batch_size=100,verbose=1,validation_data=(X_test, y_test), callbacks=[TestCallback((X_test, y_test))])

model.save(r"D:\Ammar\2-VPNvsNonVPN\Code\Models\NonVPN_"+currentdate+"_"+str(v)+".h5")
scores = model.evaluate(X_test, y_test, verbose=0)
print("Accuracy: %.2f%%" % (scores[1]*100))

y_pred1 = model.predict(X_test).argmax(axis=1)
y_test1 = y_test.argmax(axis =1)
report = classification_report( y_test1, y_pred1 )
print(report)
print(confusion_matrix(y_test1, y_pred1))
#plot_confusion_matrix(confusion_matrix(y_test1, y_pred1),labels=None)

import numpy
df = confusion_matrix(y_test1, y_pred1)

a = numpy.asarray(df)
numpy.savetxt(r"D:\Ammar\2-VPNvsNonVPN\Code\Models\ConfusionMatrix NonVPN_"+str(currentdate)+"_"+str(v)+".csv", a, delimiter=",")

