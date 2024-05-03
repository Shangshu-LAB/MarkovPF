from Pcap_Analyzer import PcapAnalyze,Quotient,BeautifulPrint_HTTPS
from Pcap_Analyzer import TCP_session
import os
from collections import Counter
import json
from pprint import pprint

rootdir='dataset_chrome_100'

for category in os.listdir(rootdir):
    # if category in ['CNN']:
    #     continue
    print(category)
    category_path=os.path.join(rootdir, category)
    i=1
    DATAs=[] #一个类别存储一个DATA的Json
    for pcapfile in os.listdir(category_path):
        pcap_path=os.path.join(category_path,pcapfile)
        print(i,pcap_path)
        i+=1
        TCP_Flows, UDP_Flows = PcapAnalyze(pcap_path,IPFilter=None,PortFilter=[443])
        Session = lambda x, y: x == y or x[0:2] + x[2:4] == y[2:4] + y[0:2]
        # pprint(list(TCP_Flows.keys()))
        DATA={}
        for key in Quotient(Session, list(TCP_Flows.keys())):
            srcIP, srcPort, dstIP, dstPort = key[0]
            # print("{0}:{1}<->{2}:{3}".format(srcIP, srcPort, dstIP, dstPort))
            session = TCP_session(srcIP, srcPort, dstIP, dstPort, 'HTTPS')
            session.Find_TCPflows(TCP_Flows)
            session_flows = session.get_Session()
            # print(session.NumOfPackets,session.BytesOfPayload)
            itoms=[] #数组记录每个广义分组数据
            for ts, direction, result in session_flows:
                itom={
                    'ts':ts,
                    'd':direction,
                    'size':len(result),
                    'frames':dict(Counter([i[0] for i in result])),
                }
                itoms.append(itom)
            if len(itoms)==0:
                continue
            DATA["{0}:{1}<->{2}:{3}".format(srcIP, srcPort, dstIP, dstPort)]={
                'NumOfPackets':session.NumOfPackets,
                'BytesOfPayload':session.BytesOfPayload,
                'data':itoms
            }
        # print(DATA)
        DATAs.append({'filename':pcapfile,'Sessions':DATA})

        # if i>2:
        #     break
    # pprint(DATAs)
    DATAs=json.dumps(DATAs)
    with open('OutputData/pcap_chrome_drop_9Percent/{0}.json'.format(category),'w') as f:
        f.write(DATAs)

