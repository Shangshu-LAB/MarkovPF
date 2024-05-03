import dpkt
import socket
import OpenSSL
from pprint import pprint
from collections import Counter


DEBUG=0

TCP_ESTABLISHED=0
TCP_CLOSED=1
class TCP_flow():
    def __init__(self,srcIP,srcPort,dstIP,dstPort):
        self.srcIP=srcIP
        self.srcPort=srcPort
        self.dstIP=dstIP
        self.dstPort=dstPort
        self.TCP_packets=[] #解析完毕后被清空

        self.state=None #TCP单向流的状态
        self.NumOfPackets = 0 #单向流中数据包总数
        self.BytesOfPayload = 0 #单向流中数据负载总字节量
        self.startTime=None
        self.endTime=None
        self.proto=None
        self.flows = []

class TCP_session():
    def __init__(self,srcIP,srcPort,dstIP,dstPort,proto):
        self.srcIP,self.srcPort = srcIP,srcPort
        self.dstIP,self.dstPort = dstIP,dstPort
        self.proto = proto
        self.TCP_flow0=[]
        self.TCP_flow1=[]
        self.NumOfPackets=0
        self.BytesOfPayload=0

    # 寻找符合要求的TCPflow来构建会话的TCP_flow0和TCP_flow1
    def Find_TCPflows(self,TCP_Flows):
        if (self.srcIP, self.srcPort, self.dstIP, self.dstPort) in TCP_Flows.keys():
            TCP_flow0 = TCP_Flows[(self.srcIP, self.srcPort, self.dstIP, self.dstPort)].flows if TCP_Flows[(self.srcIP, self.srcPort, self.dstIP, self.dstPort)].proto==self.proto else []
            self.TCP_flow0=[(ts,'>',result) for ts,result in TCP_flow0]
            self.NumOfPackets+=TCP_Flows[(self.srcIP, self.srcPort, self.dstIP, self.dstPort)].NumOfPackets
            self.BytesOfPayload+=TCP_Flows[(self.srcIP, self.srcPort, self.dstIP, self.dstPort)].BytesOfPayload
            # print(TCP_Flows[(self.srcIP, self.srcPort, self.dstIP, self.dstPort)].NumOfPackets)
        if (self.dstIP, self.dstPort, self.srcIP, self.srcPort) in TCP_Flows.keys():
            TCP_flow1 = TCP_Flows[(self.dstIP, self.dstPort, self.srcIP, self.srcPort)].flows if TCP_Flows[(self.dstIP, self.dstPort, self.srcIP, self.srcPort)].proto==self.proto else []
            self.TCP_flow1 = [(ts, '<', result) for ts, result in TCP_flow1]
            self.NumOfPackets+=TCP_Flows[(self.dstIP, self.dstPort, self.srcIP, self.srcPort)].NumOfPackets
            self.BytesOfPayload+=TCP_Flows[(self.dstIP, self.dstPort, self.srcIP, self.srcPort)].BytesOfPayload
            # print(TCP_Flows[(self.dstIP, self.dstPort, self.srcIP, self.srcPort)].NumOfPackets)


    # 将TCPflow拼接为Session
    def get_Session(self):
        flows=self.TCP_flow0+self.TCP_flow1
        flows.sort(key=lambda x:x[0])
        return flows


class UDP_flow():
    def __init__(self,srcIP,srcPort,dstIP,dstPort):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.proto=None
        self.flows = []


# TCP重组函数
def TCP_reorganization(key,TCP_flow):
    # TCP_flow.NumOfPackets = len(TCP_flow.TCP_packets) #计算单向流中数据包总数
    # TCP_flow.BytesOfPayload=0
    TCP_packets=[p for p in TCP_flow.TCP_packets if p[1].data!=b''] #删除空负载包
    TCP_flow.TCP_packets=[] #重组完成后被清空
    if len(TCP_packets)>0:
        TCP_flow.startTime=TCP_packets[0][0]
        TCP_flow.endTime=TCP_packets[-1][0]
        TCP_packets.sort(key=lambda x:x[1].seq) #排序

        Signal = 0
        Time = 0
        payload=b''
        nextseq=TCP_packets[0][1].seq
        for i in range(len(TCP_packets)):
            ts,tcp=TCP_packets[i]
            # TCP_flow.BytesOfPayload+=len(tcp.data)
            if Signal == 1: Time=ts
            ACK = 0b00010000 & tcp.flags != 0
            PSH = 0b00001000 & tcp.flags != 0
            SYN = 0b00000010 & tcp.flags != 0
            FIN = 0b00000001 & tcp.flags != 0
            # print("Seq={2},Ack={3},NextSeq={4},len={0} data: {1}".format(len(tcp.data),tcp.data,tcp.seq,tcp.ack,tcp.seq+len(tcp.data)))
            # print("Seq={0} Ack={1} NextSeq={2}, SYN={3} PSH={4} FIN={5}".format(tcp.seq,tcp.ack,tcp.seq+len(tcp.data),SYN,PSH,FIN))
            if nextseq == tcp.seq:
                if SYN == True:
                    nextseq = tcp.seq + 1
                    Signal=1
                else:
                    Signal=0
                    payload += tcp.data
                    nextseq = tcp.seq + len(tcp.data)
            else:
                continue

            # if PSH == True: #???
            #     Signal=1
            #     # 解析Payload
            #     # result=Payload_parse(key,payload)
            #     if DetermineProtocol(key)=="HTTPS":
            #         result=parse_tls(payload)
            #     else:
            #         result=("Unknown",payload)
            #     print(Time, len(payload), payload[0:50])
            #     # print("======================")
            #     # pprint(result)
            #     TCP_flow.flows.append((Time,result,payload))
            #     payload=b''
            if PSH==True:
                if i < len(TCP_packets) - 1:  # 如果不是最后一个包，检验后一个包负载
                    if DetermineTCPProtocol(key, TCP_packets[i + 1][1].data) is not False:
                        Signal = 1
                    else:
                        continue

                if DEBUG==1:
                    print(Time, len(payload), payload)

                if DetermineTCPProtocol(key, payload) == "HTTPS":
                    TCP_flow.proto="HTTPS"
                    result = parse_tls(payload)
                elif DetermineTCPProtocol(key, payload) == "HTTP":
                    TCP_flow.proto="HTTP"
                    result = parse_http(payload)
                else:
                    result = ("Unknown Protocol", payload)
                # print(len(result), result)
                TCP_flow.flows.append((Time, result))
                payload = b''
    # print()

def HTTP_PayloadFeature(buf):
    HTTPRequest_Feature = [b'GET ', b'POST',b'HEAD',b'PUT ',b'DELE',b'CONN',b'OPTI',b'TRAC',b'PATC']
    HTTPResponse_Feature = [b'HTTP']
    if buf[0:4] in HTTPRequest_Feature or buf[0:4] in HTTPResponse_Feature:
        return True
    return False

def HTTPS_PayloadFeature(buf):
    TLSType=[20,21,22,23]
    TLSVersion=[b'\x03\x01', b'\x03\x02', b'\x03\x03']
    if buf[0] in TLSType and buf[1:3] in TLSVersion:
        return True
    return False

def TCP_PortFeature(key):
    HTTPS_port=[443]
    HTTP_port=[80]
    if key[1] in HTTPS_port or key[3] in HTTPS_port:
        return "HTTPS"
    elif key[1] in HTTP_port or key[3] in HTTP_port:
        return "HTTP"
    else:
        return False

def DetermineTCPProtocol(key, buf):
    if TCP_PortFeature(key)== "HTTPS" and HTTPS_PayloadFeature(buf):
        return "HTTPS"
    elif TCP_PortFeature(key)== "HTTP" and HTTP_PayloadFeature(buf):
        return "HTTP"
    return False


def parse_http(buf):
    HTTPRequest_Feature = [b'GET ', b'POST', b'HEAD', b'PUT ', b'DELE', b'CONN', b'OPTI', b'TRAC', b'PATC']
    HTTPResponse_Feature = [b'HTTP']
    if buf[0:4] in HTTPResponse_Feature:
        result=dpkt.http.Response(buf)
    elif buf[0:4] in HTTPRequest_Feature:
        result=dpkt.http.Request(buf)
    else:
        result=('ERROR in HTTP',buf)
    return result

def parse_tls(buf):
    # SSL=dpkt.ssl.SSLFactory(buf)
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(buf)
    except:
        return ("ERROR in TLS", buf)
    Records=[]
    for record in records:
        if record.type == 22:  # handshake
            handshaketype, handshake = parse_tls_handshake(record.data)
            Records.append((handshaketype,handshake))
            # print(handshaketype,handshake)
        elif record.type == 21:  # alert
            Records.append(("alert",record))
            # print("alert",record)
        elif record.type == 20:  # change_cipher_spec
            Records.append(("change_cipher_spec", record))
            # print("change_cipher_spec", record)
        elif record.type == 23:  # application_data
            Records.append(("application_data", record.length,record.data))
            # print("application_data", record.length)
        else:
            Records.append((record.type, record))
    return Records

def parse_tls_handshake(buf):
    try:
        # print(len(buf),buf)
        handshake=dpkt.ssl.TLSHandshake(buf) #加密握手信息无法解析
    # except dpkt.ssl.SSL3Exception as e:
    #     print(e)
    #     return str(e),buf
    except: #对加密握手信息的判定可能会有问题
        return "EncryptedHandshakeMessage or ERROR",buf
    # handshake = dpkt.ssl.TLSHandshake(buf)

    if handshake.type==0: # HelloRequest
        return "HelloRequest",{}
    elif handshake.type==1: # ClientHello
        ClientHello=handshake.data
        # print(dpkt.ssl.parse_extensions(ClientHello.extensions))
        # for extension in ClientHello.extensions:
        #     print(extension[0],extension[1])
        ciphersuites=[ClientHello.ciphersuites[2*i:2*i+2].hex() for i in range(int(ClientHello.num_ciphersuites))]
        return "ClientHello",{
            "random":int.from_bytes(ClientHello.random,byteorder='big'), # 格式问题
            "session_id":int.from_bytes(ClientHello.session_id,byteorder='big'), # 格式问题
            "num_ciphersuites":int(ClientHello.num_ciphersuites), #缺少对CS的解析
            "ciphersuites":ciphersuites,
            "num_compression_methods":ClientHello.num_compression_methods,
            "compression_methods":ClientHello.compression_methods, # 尚需进一步解析
            "extensions": ClientHello.extensions # 格式问题
        }
    elif handshake.type==2: # ServerHello
        ServerHello=handshake.data
        # print(hex(ServerHello.cipher_suite))
        return "ServerHello",{
            "random": int.from_bytes(ServerHello.random,byteorder='big'), # 格式问题
            "session_id":int.from_bytes(ServerHello.session_id,byteorder='big'), # 格式问题
            "cipher_suite":hex(ServerHello.cipher_suite)[2:], # 格式问题
            "compression":ServerHello.compression, # 格式问题
            "extensions":ServerHello.extensions # 格式问题
        }
    elif handshake.type==4: # New Session Ticket
        return "NewSessionTicket",{}
    elif handshake.type==11: # Certificate
        Certificates=handshake.data.certificates
        certs=[]
        for Certificate in Certificates:
            cert=parse_Certificate(Certificate)
            certs.append(cert)
        return "Certificates",certs
    elif handshake.type==12: # ServerKeyExchange
        return "ServerKeyExchange",{}
    elif handshake.type==13: # CertificateRequest
        return "CertificateRequest",{}
    elif handshake.type==14: # ServerHelloDone
        return "ServerHelloDone",{}
    elif handshake.type==15: # CertificateVerify
        return "CertificateVerify",{}
    elif handshake.type==16: # ClientKeyExchange
        return "ClientKeyExchange",{}
    elif handshake.type==20: # Finished
        return "Finished",{}
    else:
        # print(handshake)
        return "Unknown type {0}".format(handshake.type),{}

def parse_Certificate(buf):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, buf)
    issuer = cert.get_issuer() # need further analyze
    subject = cert.get_subject() # need further analyze
    extensions={}
    for index in range(cert.get_extension_count()):
        extension = cert.get_extension(index)
        extensions[extension.get_short_name().decode()]=extension.get_data()
    # pprint(extensions)
    return {
        "version": cert.get_version() + 1,
        "SerialName": cert.get_serial_number(),
        "signature_algorithm": cert.get_signature_algorithm().decode(),
        "Validity_NotBefore": cert.get_notBefore().decode(),
        "Validity_NotAfter": cert.get_notAfter().decode(),
        "Issuer": {itom[0].decode():itom[1].decode() for itom in issuer.get_components()},
        "Subject": {itom[0].decode():itom[1].decode() for itom in subject.get_components()},
        "pubkey": cert.get_pubkey(), # 格式问题
        "extension_num": cert.get_extension_count(),
        "extensions":extensions
    }

def DetermineUDPProtocol_byPort(key):
    DNS_port=[53]
    if key[1] in DNS_port or key[3] in DNS_port:
        return "DNS"
    else:
        return False
def parse_UDP(key,buf):
    if DetermineUDPProtocol_byPort(key)=="DNS":
        result=parse_DNS(buf)
        return result
    return buf

def parse_DNS(buf):
    dns=dpkt.dns.DNS(buf)
    QD = [q.name for q in dns.qd]
    ANs = []
    for rr in dns.an:
        AN = {"name": rr.name, "ttl": rr.ttl}
        if rr.type == 1:
            AN["ip"] = socket.inet_ntop(socket.AF_INET, rr.ip)
        elif rr.type == 5:
            AN["cname"] = rr.cname
        ANs.append(AN)
    # print("NS",dns.ns)
    # print("AR",dns.ar)
    return {"QD":QD,"AN":ANs}

def Filter(key,IPFilter,PortFilter):
    srcIP, srcPort, dstIP, dstPort=key
    if IPFilter is not None:
        if srcIP not in IPFilter and dstIP not in IPFilter:
            return False
    if PortFilter is not None:
        if srcPort not in PortFilter and dstPort not in PortFilter:
            return False
    return True

def PcapAnalyze(Pcapfile,IPFilter=None,PortFilter=None):
    # 打开文件
    f = open(Pcapfile, 'rb')
    filetype = Pcapfile.split('.')[-1]
    if filetype == 'pcapng':
        packets = dpkt.pcapng.Reader(f)
    elif filetype == 'pcap':
        packets = dpkt.pcap.Reader(f)
    else:
        Exception("Error with Traffic File")

    TCP_Flows,UDP_Flows = {},{}
    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            pass
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            srcIP = socket.inet_ntop(socket.AF_INET, ip.src)
            dstIP = socket.inet_ntop(socket.AF_INET, ip.dst)
            # srcPort=ip.data.sport
            # dstPort=ip.data.dport
            if ip.p==6: # TCP
                tcp = ip.data
                srcPort, dstPort = tcp.sport, tcp.dport
                key = (srcIP, srcPort, dstIP, dstPort)
                if Filter(key,IPFilter,PortFilter) is False: #过滤
                    continue
                if key in TCP_Flows.keys():
                    TCP_Flows[key].TCP_packets.append((ts, tcp))
                else:
                    TCP_Flows[key] = TCP_flow(srcIP, srcPort, dstIP, dstPort)
                    TCP_Flows[key].state=TCP_ESTABLISHED #设置TCPflow状态为建立
                    TCP_Flows[key].TCP_packets.append((ts, tcp))
                TCP_Flows[key].NumOfPackets+=1
                TCP_Flows[key].BytesOfPayload+=len(tcp.data)
                Seq, Ack, NextSeq = tcp.seq, tcp.ack, tcp.seq + len(tcp.data)
                ACK = 0b00010000 & tcp.flags != 0
                PSH = 0b00001000 & tcp.flags != 0
                SYN = 0b00000010 & tcp.flags != 0
                FIN = 0b00000001 & tcp.flags != 0
                # print("Seq={0},Ack={1},NextSeq={2}".format(Seq,Ack,NextSeq),ACK,PSH,SYN,FIN)
                if FIN == True and TCP_Flows[key].state==TCP_ESTABLISHED:  # 会话关闭
                    if DEBUG == 1:
                        print("{0}:{1}->{2}:{3}".format(key[0],key[1],key[2],key[3]))
                    # 分段重组 参数为 TCP_Flows[key].Payloads
                    TCP_Flows[key].state=TCP_CLOSED #设置TCPflow状态为关闭
                    TCP_reorganization(key, TCP_Flows[key])
                    # 对于可以修改的对象，如列表和字典，函数的参数传递方式是引用传递。
                    # 对于不能修改的对象，包括字符串、一般变量和元组（元组本来就不能修改），参数传递的方式是值传递。
                    if DEBUG == 1:
                        print()
                #需要讨论如果会话未关闭的情况
            elif ip.p==17: # UDP
                udp = ip.data
                srcPort, dstPort = udp.sport, udp.dport
                key = (srcIP, srcPort, dstIP, dstPort)
                if Filter(key,IPFilter,PortFilter) is False: #过滤
                    continue
                if key not in UDP_Flows.keys():
                    UDP_Flows[key] = UDP_flow(srcIP, srcPort, dstIP, dstPort)
                result = parse_UDP(key, udp.data)
                # print("{0}:{1}->{2}:{3}".format(key[0], key[1], key[2], key[3]))
                # print(result)
                UDP_Flows[key].flows.append((ts, result))
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
            else:
                pass

    # 对所有未关闭的TCP流进行处理
    for key in TCP_Flows.keys():
        if TCP_Flows[key].state==TCP_ESTABLISHED:
            if DEBUG == 1:
                print("{0}:{1}->{2}:{3}".format(key[0], key[1], key[2], key[3]))
            TCP_Flows[key].state = TCP_CLOSED  # 设置TCPflow状态为关闭
            TCP_reorganization(key, TCP_Flows[key])
            if DEBUG == 1:
                print()

    return TCP_Flows,UDP_flow

def BeautifulPrint_HTTPS(flows):
    for ts,direction,result in flows:
        print(ts,direction,len(result),dict(Counter([i[0] for i in result])))

def BeautifulPrint_HTTP(flows):
    for ts,direction,result in flows:
        print(ts,direction)
        print(result)

def Quotient(f,N):
    QuotientSet=[]
    while len(N)>0:
        Now=N.pop(0)
        NowSet=[Now]
        Nodes=[]
        for j in N:
            if f(Now,j) is True:
                NowSet.append(j)
                Nodes.append(j)
        QuotientSet.append(NowSet)
        for j in Nodes:
            N.remove(j)
    return QuotientSet



if __name__=="__main__":
    Pcapfile="Data.pcap"

    # TCP_Flows包含所有TCP流, UDP_Flows包含所有UDP流
    # 过滤器为列表
    TCP_Flows,UDP_Flows=PcapAnalyze(Pcapfile,IPFilter=None,PortFilter=[443])
    # TCP_Flows, UDP_Flows = PcapAnalyze(Pcapfile, IPFilter=None, PortFilter=[443])
    Session=lambda x,y:x==y or x[0:2]+x[2:4]==y[2:4]+y[0:2]
    # pprint(list(TCP_Flows.keys()))

    # 通过商集得出所有会话，然后遍历
    for key in Quotient(Session,list(TCP_Flows.keys())):
        srcIP, srcPort, dstIP, dstPort=key[0]
        print("{0}:{1}<->{2}:{3}".format(srcIP, srcPort, dstIP, dstPort))
        session = TCP_session(srcIP, srcPort, dstIP, dstPort, 'HTTPS')
        session.Find_TCPflows(TCP_Flows)
        data = session.get_Session()
        print(session.NumOfPackets,session.BytesOfPayload/1024)
        # BeautifulPrint_HTTPS(data)
        # BeautifulPrint_HTTP(data)
        print()

    # example=TCP_session('10.0.0.1', 65052, '212.179.154.245', 443,'HTTPS')
    # example.Find_TCPflows(TCP_Flows)
    # data=example.get_Session()
    #
    # BeautifulPrint_HTTPS(data)



