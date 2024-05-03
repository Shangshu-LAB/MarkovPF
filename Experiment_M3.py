from Basic import get_Markov_Order3
from Basic import get_Traffic,Predict
import os
import re
from collections import Counter
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime


if __name__=='__main__':
    np.set_printoptions(precision=0)
    rootdir='DataSet/Train'
    MaxNum = 40
    BoxSize = 5
    TrainSize = 20
    Model={}
    a = datetime.now()
    for Jsonfile in os.listdir(rootdir):
        with open(os.path.join(rootdir, Jsonfile), 'r') as f:
            Jsondatas=json.loads(f.read())
        category=Jsonfile.split('.')[0]
        # print(category, len(Jsondatas))
        Markov = np.zeros((MaxNum, MaxNum,MaxNum,MaxNum))
        for Jsondata in Jsondatas[0:TrainSize]:
            filename=Jsondata['filename']
            Sessions=Jsondata['Sessions']
            VideoTraffic,AudioTraffic=get_Traffic(Sessions=Sessions)
            # print(filename,VideoTraffic)
            Markov+=get_Markov_Order3(VideoTraffic, MaxNum=MaxNum, BoxSize=BoxSize)
        # Markov=Markov / len(Jsondatas)
        for i in range(MaxNum):
            for j in range(MaxNum):
                for k in range(MaxNum):
                    Markov[i][j][k]=Markov[i][j][k]/Markov[i][j][k].sum() if Markov[i][j][k].sum()>0 else 0
        Model[category] = Markov
        # 绘制图像
        # ax = sns.heatmap(Markov, vmin=0, vmax=Markov.max(), cmap='Greens')
        # plt.title(category)
        # plt.show()
        # print()
    b = datetime.now()
    TrainTime = (b - a).seconds
    print("=====================Test=============================")

    # 设置混淆矩阵
    categorys = [i.split('.')[0] for i in os.listdir('OutputData/')]
    ConfusionMatrix = pd.DataFrame(data=None, columns=categorys)

    rootdir='DataSet/Test'
    TP,ALL=0,0
    RESULT = {
        'info': {'MaxNum': MaxNum, 'BoxSize': BoxSize},
        'result': {},
        'TrainTime': TrainTime,
        'TestTime': None,
        'accuracy': None,
    }
    a = datetime.now()
    for Jsonfile in os.listdir(rootdir):
        with open(os.path.join(rootdir, Jsonfile), 'r') as f:
            Jsondatas=json.loads(f.read())
        category=Jsonfile.split('.')[0]
        # print(category, len(Jsondatas))
        PredictResult=[]
        for Jsondata in Jsondatas:
            filename=Jsondata['filename']
            Sessions=Jsondata['Sessions']
            VideoTraffic, AudioTraffic = get_Traffic(Sessions=Sessions)
            Markov=get_Markov_Order3(Traffic=VideoTraffic, MaxNum=MaxNum, BoxSize=BoxSize)
            result=Predict(Model,Markov)
            PredictResult.append(result)
            # if result!=category:
            #     print(filename,VideoTraffic)
        right=Counter(PredictResult)[category]
        Accurancy=right/len(PredictResult)
        print(category,Accurancy)
        RESULT['result'][category] = Accurancy
        TP += right
        ALL += len(PredictResult)
        ConfusionMatrix.loc[category]=pd.Series(Counter(PredictResult))
        # print(Counter(PredictResult))
    b = datetime.now()
    TestTime = (b - a).seconds
    print(TrainTime)
    print(TestTime)
    print(TP/ALL)
    RESULT['TestTime'] = TestTime
    RESULT['accuracy'] = TP / ALL
    Name = '{0}order_{3}_{1}-{2}.json'.format(3, MaxNum, BoxSize,TrainSize)
    with open('result0/' + Name, 'w') as f:
        f.write(json.dumps(RESULT))

    ConfusionMatrix=ConfusionMatrix.fillna(0)
    ConfusionMatrix.to_csv('result.csv')
    # # plt.figure(figsize=(10, 10))
    ax = sns.heatmap(ConfusionMatrix, cmap='Greens')
    plt.xticks(rotation=90,fontsize=5)
    plt.yticks(rotation=0,fontsize=5)
    plt.title('ConfusionMatrix')
    plt.show()
    #
