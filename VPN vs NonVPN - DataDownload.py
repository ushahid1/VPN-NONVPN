import pandas as pd
import csv
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess
import os.path


def clickOnAd(driver):
    try:
        res = driver.find_element_by_xpath("//*[contains(text(),'Skip Ad')]").click()        
    except:
        print("didn't find ad video ad insertion")
#The function receive a string indicate the requested video quality
def downloadVideo(video_quality,video_name, url, duration_of_the_video):
    t_time = time.strftime("%H_%M_%S")
    funcInFile = "Test"
    
    root_path = "D:\\Ammar\\VPN Stream\\Code"
    
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    
    video_path = root_path + video_name +"\\"
    if not os.path.exists(video_path):
        os.makedirs(video_path)

    quality_path =  video_path + "\\"
    if not os.path.exists(quality_path):
        os.makedirs(quality_path)

    filename = quality_path + video_name + "_"  + funcInFile + t_time + ".pcap"
    tsharkOut  = open(filename, "wb")
    tsharkCall = ["C:\\Program Files\\Wireshark\\tshark.exe","-F", "pcap", "-f", "port 51820", "-i", "4", "-w", filename] #port 56847 and 51820
    
    tsharkProc = subprocess.Popen(tsharkCall, stdout=tsharkOut, executable="C:\\Program Files\\Wireshark\\tshark.exe")
    chrome_options = webdriver.ChromeOptions()

    chrome_options.binary_location ="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    chrome_options.add_extension('adblock.crx')
   

    #chrome_options.add_extension('Ultrasurf.crx')
    
    driver = webdriver.Chrome(executable_path='chromedriver.exe',options=chrome_options)

    wait = WebDriverWait(driver, 20)
    driver.get(url)
    
    start_time = time.time()
    
    main_window = driver.current_window_handle
    
    #driver.find_element_by_tag_name('body').send_keys(Keys.CONTROL + 'w')
    driver.switch_to_window(main_window)
    
    time.sleep(10)
    
    clickOnAd(driver)
    time.sleep(2)
    clickOnAd(driver)
    
    timersetting = False
    time.sleep(10)
    
    try:
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
    
    
def harvest_video(amount,name,url,duration):
    for x in range(0, amount):
        print('{} run number:{}'.format(name,x))
        downloadVideo("Auto",name,url,duration)
        
        
data = pd.read_csv("links.csv")

i=0
while i < len(data['id']):
   
    filename = str(data['id'][i])
    urlF = str(data['Links'][i])
    amount = int(data['numbers'][i])
    link100_url = urlF
    link100_duration = 120
    harvest_video(amount,filename,link100_url,link100_duration)
    i+=1