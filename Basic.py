import re
import random
import numpy as np


ClienrIPs=[
    '10.0.0.1','10.0.0.3','10.0.0.4','10.0.0.6',
    '10.10.50.165',
    '192.168.1.207'
]

def get_Traffic(Sessions):
    '''
    从Json文件中获得VideoTraffic和AudioTraffic序列
    :param Sessions:从传入JsonData['Sessions']
    :return: VideoTraffic,AudioTraffic
    '''
    Example = [(key, Sessions[key]['NumOfPackets'], Sessions[key]['BytesOfPayload']) for key in Sessions.keys()]
    Example.sort(key=lambda x: x[1], reverse=True)
    VideoKey = Example[0][0]
    AudioKey = Example[1][0]
    # print(VideoKey,AudioKey)
    direction = '>' if re.split(r':|<->', VideoKey)[3] in ClienrIPs else '<'  # 此处本地IP不一定是10.0.0.1
    # print(Sessions[VideoKey]['data'])
    VideoTraffic = [i['size'] for i in Sessions[VideoKey]['data'] if i['d'] == direction]
    AudioTraffic = Sessions[AudioKey]
    return VideoTraffic,AudioTraffic

def get_Traffic_(Sessions):
    '''
    从Json文件中获得VideoTraffic和AudioTraffic序列
    :param Sessions:从传入JsonData['Sessions']
    :return: VideoTraffic,AudioTraffic
    '''
    Example = [(key, Sessions[key]['NumOfPackets'], Sessions[key]['BytesOfPayload']) for key in Sessions.keys()]
    Example.sort(key=lambda x: x[1], reverse=True)
    VideoKey = Example[0][0]
    AudioKey = Example[1][0]
    # print(VideoKey,AudioKey)
    direction = '>' if re.split(r':|<->', VideoKey)[3] in ClienrIPs else '<'  # 此处本地IP不一定是10.0.0.1
    VideoTraffic = [i['frames']['application_data'] for i in Sessions[VideoKey]['data'] if i['d'] == direction and 'application_data' in i['frames'].keys()]
    AudioTraffic = Sessions[AudioKey]
    return VideoTraffic,AudioTraffic

def get_Markov(Traffic,MaxNum=15,BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Markov矩阵
    :param Traffic:流量序列
    :return: Markov矩阵
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Markov = np.zeros((MaxNum, MaxNum))
    for i in range(len(Traffic) - 1):
        x = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        y = Traffic[i + 1] if Traffic[i + 1] < MaxNum else MaxNum - 1
        Markov[x][y] += 1
    return Markov

def get_Markov_Order2(Traffic, MaxNum=15, BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Markov矩阵
    :param Traffic:流量序列
    :return: Markov矩阵
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Markov = np.zeros((MaxNum, MaxNum,MaxNum))
    for i in range(len(Traffic) - 2):
        x = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        y = Traffic[i + 1] if Traffic[i + 1] < MaxNum else MaxNum - 1
        z = Traffic[i + 2] if Traffic[i + 2] < MaxNum else MaxNum - 1
        Markov[x][y][z] += 1
    return Markov

def get_Markov_Order3(Traffic, MaxNum=15, BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Markov矩阵
    :param Traffic:流量序列
    :return: Markov矩阵
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Markov = np.zeros((MaxNum, MaxNum, MaxNum, MaxNum))
    for i in range(len(Traffic) - 3):
        x = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        y = Traffic[i + 1] if Traffic[i + 1] < MaxNum else MaxNum - 1
        z = Traffic[i + 2] if Traffic[i + 2] < MaxNum else MaxNum - 1
        t = Traffic[i + 3] if Traffic[i + 3] < MaxNum else MaxNum - 1
        Markov[x][y][z][t] += 1
    return Markov

def get_Markov_Order4(Traffic, MaxNum=15, BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Markov矩阵
    :param Traffic:流量序列
    :return: Markov矩阵
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Markov = np.zeros((MaxNum, MaxNum, MaxNum, MaxNum, MaxNum))
    for i in range(len(Traffic) - 4):
        x = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        y = Traffic[i + 1] if Traffic[i + 1] < MaxNum else MaxNum - 1
        z = Traffic[i + 2] if Traffic[i + 2] < MaxNum else MaxNum - 1
        t = Traffic[i + 3] if Traffic[i + 3] < MaxNum else MaxNum - 1
        u = Traffic[i + 4] if Traffic[i + 4] < MaxNum else MaxNum - 1
        Markov[x][y][z][t][u] += 1
    return Markov

def get_Markov_Order5(Traffic, MaxNum=15, BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Markov矩阵
    :param Traffic:流量序列
    :return: Markov矩阵
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Markov = np.zeros((MaxNum, MaxNum, MaxNum, MaxNum, MaxNum, MaxNum))
    for i in range(len(Traffic) - 5):
        x = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        y = Traffic[i + 1] if Traffic[i + 1] < MaxNum else MaxNum - 1
        z = Traffic[i + 2] if Traffic[i + 2] < MaxNum else MaxNum - 1
        t = Traffic[i + 3] if Traffic[i + 3] < MaxNum else MaxNum - 1
        u = Traffic[i + 4] if Traffic[i + 4] < MaxNum else MaxNum - 1
        v = Traffic[i + 5] if Traffic[i + 5] < MaxNum else MaxNum - 1
        Markov[x][y][z][t][u][v] += 1
    return Markov


def get_Sequence(Traffic,MaxNum=15,BoxSize=10):
    '''
    对Traffic序列进行统计，转换成Sequence向量
    :param Traffic:流量序列
    :return: Sequence向量
    '''
    Traffic=[int(i/BoxSize) for i in Traffic]
    Seqence=[]
    for i in range(len(Traffic)):
        s = Traffic[i] if Traffic[i] < MaxNum else MaxNum - 1
        Seqence.append(s)
    return Seqence

def Predict(Model,Markov):
    '''
    # 使用模型进行预测
    :param Model:
    :param Markov:
    :return:
    '''
    result=None
    MaxValue=0
    for key in Model.keys():
        Value=Model[key]*Markov
        if Value.sum()>MaxValue:
            MaxValue=Value.sum()
            result=key
        elif Value.sum()==MaxValue:
            if random.randint(0,1)==1:
                result=key
    return result

def Predict_1order(Model,Sequence):
    '''
    # 使用模型进行预测
    :param Model:
    :param Markov:
    :return:
    '''
    result=None
    MaxValue=0
    for key in Model.keys():
        Value=1.0
        for i in range(len(Sequence)-1):
            Value*=Model[key][Sequence[i]][Sequence[i+1]]
        if Value>MaxValue:
            MaxValue=Value
            result=key
        elif Value==MaxValue:
            if random.randint(0,1)==1:
                result=key
    return result
