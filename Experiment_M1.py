from Basic import get_Markov,get_Sequence
from Basic import get_Traffic,Predict_1order
import os
from collections import Counter
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pprint import pprint
from datetime import datetime

if __name__=='__main__':
    np.set_printoptions(precision=0)
    rootdir='DataSet/Train'
    MaxNum = 40
    BoxSize = 5
    Model={}
    TrainSize=50

    a=datetime.now()
    for Jsonfile in os.listdir(rootdir):
        with open(os.path.join(rootdir, Jsonfile), 'r') as f:
            Jsondatas=json.loads(f.read())
        category=Jsonfile.split('.')[0]
        # print(category, len(Jsondatas))
        Markov = np.zeros((MaxNum, MaxNum))
        for Jsondata in Jsondatas:
            filename=Jsondata['filename']
            Sessions=Jsondata['Sessions']
            VideoTraffic,AudioTraffic=get_Traffic(Sessions=Sessions)
            # print(filename,VideoTraffic)
            Markov+=get_Markov(VideoTraffic,MaxNum=MaxNum,BoxSize=BoxSize)
        # Markov=Markov / len(Jsondatas)
        for i in range(MaxNum):
            Markov[i]=Markov[i]/Markov[i].sum() if Markov[i].sum()>0 else 0
        Model[category] = Markov
        # 绘制图像
        # ax = sns.heatmap(Markov, vmin=0, vmax=Markov.max(), cmap='Greens')
        # plt.title(category)
        # plt.show()
        # print()
    b=datetime.now()
    TrainTime=(b-a).seconds
    print("=====================Test=============================")

    # 设置混淆矩阵
    categorys = [i.split('.')[0] for i in os.listdir(rootdir)]
    ConfusionMatrix = pd.DataFrame(data=None, columns=categorys)

    rootdir='DataSet/Test'
    TP,ALL=0,0
    RESULT = {
        'info': {'MaxNum': MaxNum, 'BoxSize': BoxSize},
        'result': {},
        'TrainTime':TrainTime,
        'TestTime':None,
        'accuracy': None,
    }
    a=datetime.now()
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
            Sequence=get_Sequence(Traffic=VideoTraffic,MaxNum=MaxNum,BoxSize=BoxSize)
            result=Predict_1order(Model,Sequence)
            PredictResult.append(result)
            # if result!=category:
            #     print(filename,VideoTraffic)
        right=Counter(PredictResult)[category]
        Accurancy=right/len(PredictResult)
        print(category,Accurancy)
        RESULT['result'][category] = Accurancy
        TP+=right
        ALL+=len(PredictResult)
        ConfusionMatrix.loc[category]=pd.Series(Counter(PredictResult))
        print(ConfusionMatrix.loc[category])
    b=datetime.now()
    TestTime=(b-a).seconds
    print(TrainTime)
    print(TestTime)
    print(TP/ALL)
    RESULT['TestTime']=TestTime
    RESULT['accuracy'] = TP / ALL
    Name = '{0}order_{1}-{2}.json'.format(1, MaxNum, BoxSize)
    with open('result/' + Name, 'w') as f:
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
