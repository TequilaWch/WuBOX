# 两个部分：（1）根据白名单csv生成knn模型并保存（2）利用knn模型判断新来的。

from re import L
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier as KNN
from sklearn.neighbors import RadiusNeighborsClassifier as RNN
from sklearn.decomposition import PCA
from sklearn import neighbors
import joblib
import pylab as pl
import os
import warnings
warnings.filterwarnings("ignore")
# 相对路径
whitelist_csv_dir = '../whitelist/csv/'
whitelist_model_dir = '../whitelist/model/'

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
    # print(whitelistset)
    for i in range(len(whitelist)):
        temp = pd.read_csv(whitelist[i])
        # 去重
        temp = temp.drop_duplicates()
        # print(temp)
        # print("\n")
        whitelistset  = pd.concat([whitelistset,temp],ignore_index=True)
    # print(whitelistset[0:1][["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]].values.tolist())
    offset = 0
    for i in range(len(whitelistset)):
        # 去掉不足片段长度的干扰点
        if sum(whitelistset[i-offset:i+1-offset][["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]].values.tolist()[0]) != 1500:
            whitelistset = whitelistset.drop(index=i)
            offset +=1
            
    # print(whitelistset)
    return whitelistset

# def get_csv():
#     global whitelist_csv_dir
#     all_whitelist = []
#     files = os.listdir(whitelist_csv_dir)
#     for i in files:
#         if os.path.splitext(i)[1] == ".csv":
#             all_whitelist.append(whitelist_csv_dir + i)
#     return all_whitelist

def get_listset(lists):
    listset = pd.DataFrame(None, columns=["fork","execve","read","write","open","close","socket","connect","accept","send","recv","type"],index=None)
    # print(whitelistset)
    for i in range(len(lists)):
        temp = pd.read_csv(lists[i])
        # 去重
        temp = temp.drop_duplicates()
        temp.insert(loc=len(temp.columns), column='type', value=5)
        # print(temp)
        # print("\n")
        listset  = pd.concat([listset,temp],ignore_index=True)
    # print(whitelistset[0:1][["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]].values.tolist())
    offset = 0
    for i in range(len(listset)):
        # 去掉不足片段长度的干扰点
        if sum(listset[i-offset:i+1-offset][["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]].values.tolist()[0]) != 1500:
            listset = listset.drop(index=i)
            offset +=1
            continue
        # 去掉合法点
        if category(listset[i-offset:i+1-offset][["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]]):
            listset = listset.drop(index=i)
            offset +=1
            continue
    # print(whitelistset)
    return listset

# 数据可视化
def showscatter(data):
    # 降维
    data_data = data[["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]]
    data_type = data[["type"]]
    # print(np.array(data_type).tolist())
    # print(data_type['type'].tolist())
    newdata = PCA(n_components=2).fit_transform(data_data)
    # print(type(newdata)) 
    map_color = {0: 'darkorange', 1: 'darkgreen', 2:"royalblue",3:"indigo",4:"darkred"}
    # print(data_type['type'])
    # color = list(map(lambda x: map_color[x], data_type['type'][:-3].tolist()))
    color = list(map(lambda x: map_color[x], data_type['type'].tolist()))
    plt.scatter(np.array(newdata[:, 0]), np.array(newdata[:, 1]), c=color, marker='o', alpha=0.8)
    # map_marker = {0: 'o', 1: 'o', 2:"o",3:"o",4:"o",5:"x"}
    # marker = list(map(lambda x: map_marker[x], data_type['type'].tolist()))
    # plt.scatter(np.array(newdata[:-3, 0]), np.array(newdata[:-3, 1]), c=color, marker='o', alpha=0.8)
    # plt.scatter(np.array(newdata[-3:, 0]), np.array(newdata[-3:, 1]), c="black", marker='x')
    plt.show()

# 训练kNN模型并保存
def kNNgen(k=5):
    csvlist = get_whitelist_csv()
    whitelist = get_whitelistset(csvlist)
    # 类型标签修改
    data = whitelist
    types = list(set(whitelist['type']))
    knum = len(types)
    ktype = {}
    num2type = {}
    for i in range(knum):
        ktype[types[i]] = i
        num2type[i] = types[i]
    for i in range(knum):
        data.loc[data['type'] == types[i], 'type'] = ktype[types[i]]
    # print(data)
    # return data
    # 绘制白名单图像
    showscatter(data)
    # KNN 模型生成
    print("正在训练白名单模型")
    X_train = data[["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]]
    Y_train = data[["type"]].values
    # print(X_train)
    # print(Y_train)
    knnmodel = KNN(n_neighbors=k)
    # print(knnmodel)
    knnmodel.fit(X_train,Y_train.ravel().astype('int')) 
    # # 模型保存
    joblib.dump(knnmodel,whitelist_model_dir+'whitelist.pkl')
    print("白名单数据种数：%d \t 分别为：" % knum, types)
    print("白名单准确率:" + str(knnmodel.score(X_train, Y_train.ravel().astype('int'))))
    print("白名单被保存于\'WUBOX\\whitelist\\model\\whitelist.pkl\'")
    return data
def category(point, k = 5, distance = 50, pkl = "whitelist.pkl"):
    # 导入模型并预测
    knn = joblib.load(whitelist_model_dir+pkl) 
    # test = [[0,5,4884,4748,229,134,0,0,0,0,0]]
    # print(knn.predict(point))
    # 返回距离
    array = knn.kneighbors(point, k, return_distance=True)
    # print(array)
    # print(array[0][0,0])
    # print(array[0][0,1])

    # 默认从小到大排距离，如果最近的最小距离超过设置的distance则认为是新的，不可用, 
    # 如果最近点到次近点距离过大，也认为G
    if array[0][0,0] > distance:
        # print("Error: Not exist in whitelist")
        return False
    else:
        return True



if __name__ == "__main__":
    # csvlist = get_whitelist_csv()
    # whitelist = get_whitelistset(csvlist)
    # blacklist = ["../appinfo/blackscholes.csv","../appinfo/rtview.csv","../appinfo/dedup.csv"]
    # black = get_listset(blacklist)
    # print(black)
    kNNgen(k=5)
    # white = kNNgen()
    # all = pd.concat([white,black],ignore_index=True)
    # showscatter(all)
    # test = [[0,5,4884,4748,229,134,0,0,0,0,0]]
    # category(test)