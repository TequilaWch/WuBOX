# 两个部分：（1）根据白名单csv生成knn模型并保存（2）利用knn模型判断新来的。

from re import L
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier as KNN
from sklearn.metrics import accuracy_score,\
    classification_report, confusion_matrix
import joblib
import pylab as pl
import os
# 相对路径
whitelist_csv_dir = '../whitelist/csv/'

# 读取所有白名单csv 
def get_whitelist_csv():
    global whitelist_csv_dir
    all_whitelist = []
    files = os.listdir(whitelist_csv_dir)
    for i in files:
        if os.path.splitext(i)[1] == ".csv":
            all_whitelist.append(whitelist_csv_dir + i)
    return all_whitelist

# 读取白名单csv中数据
def get_whitelistset(whitelist):
    whitelistset = pd.DataFrame(None, columns=["fork","execve","read","write","open","close","socket","connect","accept","send","recv","type"],index=None)
    # print(whitelistset.columns)
    for i in range(len(whitelist)):
        temp = pd.read_csv(whitelist[i], index_col=0).reset_index(drop=True)
        whitelistset  = pd.concat([whitelistset,temp],ignore_index=True)
        # print(whitelistset)
    return whitelistset


# 训练kNN模型并保存
def kNNgen(whitelist):
    data = whitelist
    types = list(set(whitelist['type']))
    knum = len(types)
    ktype = {}
    for i in range(knum):
        ktype[types[i]] = i
    for i in range(knum):
        data.loc[data['type'] == types[i], 'type'] = ktype[types[i]]
    print(data)


if __name__ == "__main__":
    csvlist = get_whitelist_csv()
    whitelist = get_whitelistset(csvlist)
    kNNgen(whitelist)