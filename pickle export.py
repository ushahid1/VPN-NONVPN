# -*- coding: utf-8 -*-
"""
Created on Mon Dec  6 10:20:49 2021

@author: ServerCUI
"""

import pickle
import csv
import pandas as pd




testing_file_path = "D:\\Ammar\\2-VPNvsNonVPN\\Code\\Models\\Testing.csv"
data_test = pd.read_csv(testing_file_path)
y2=data_test.iloc[:,-1]
l_temp2=pd.get_dummies(y2)
l_temp2.to_pickle("D:\\Ammar\\2-VPNvsNonVPN\\Code\\Models\\Testing.pkl")
