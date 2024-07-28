from scapy.all import *
from apscheduler.schedulers.background import BackgroundScheduler
import argparse
import pandas as pd
from matplotlib import pyplot as plt
import numpy as np
import scipy as sp


cnt = 0
bytes_record = [] # 用于记录吞吐率


# 在线记录吞吐率，1s清空一次
def record_throughput():
    global cnt
    bytes_record.append(cnt)
    cnt = 0

# 记录传输字节数
def throughput(pkt):
    global cnt
    if pkt.haslayer("UDP") and pkt["UDP"].dport == 4791:
        payload_length = pkt["UDP"].len
        cnt = cnt + payload_length


# 打印报文信息
def print_info(pkt, only_nak=False):
    src_ip = pkt["IP"].src
    dst_ip = pkt["IP"].dst
    tos = pkt["IP"].tos
    ecn = tos & 3
    sport = pkt["UDP"].sport
    dport = pkt["UDP"].dport
    payload_length = pkt["UDP"].len
    opcode = pkt["UDP"].load[0]
    dst_qpn = int.from_bytes(pkt["UDP"].load[5:8], byteorder='big')
    psn = int.from_bytes(pkt["UDP"].load[9:12], byteorder='big')

    info_str = f"sip:{src_ip} dip:{dst_ip} ecn:{ecn} sport:{sport} dport:{dport} udp length:{payload_length} opcode:{opcode} dst qpn:{dst_qpn} psn:{psn} "
    
    if opcode & 31 == 10 or opcode & 31 == 12:
        rkey = int.from_bytes(pkt["UDP"].load[20:24], byteorder='big')
        info_str += f"rkey:{rkey} "

    # 丢包报文判断
    if opcode == 17:
        if pkt["UDP"].load[12] & 32 != 0:
            info_str += " ACK: NAK"
            print(info_str)
        elif not only_nak:
            info_str += " ACK: ACK"
            print(info_str)
    elif not only_nak:
        print(info_str)

# 序列化
def serialize_pkt(pkt, file):
    src_ip = pkt["IP"].src
    dst_ip = pkt["IP"].dst
    tos = pkt["IP"].tos
    ecn = tos & 3
    sport = pkt["UDP"].sport
    dport = pkt["UDP"].dport
    payload_length = pkt["UDP"].len
    opcode = pkt["UDP"].load[0]
    dst_qpn = int.from_bytes(pkt["UDP"].load[5:8], byteorder='big')
    psn = int.from_bytes(pkt["UDP"].load[9:12], byteorder='big')
    rkey = int.from_bytes(pkt["UDP"].load[20:24], byteorder='big') if opcode & 31 in [10, 12] else 0

    with open(file, 'ab') as f:
        f.write(struct.pack('16s16sBBHHHHIII', 
                            src_ip.encode('utf-8'), 
                            dst_ip.encode('utf-8'), 
                            tos, ecn, sport, dport, payload_length, 
                            opcode, dst_qpn, psn, rkey))

# 反序列化
def deserialize_pkt(file):
    with open(file, 'rb') as f:
        while chunk := f.read(56):  
            src_ip, dst_ip, tos, ecn, sport, dport, payload_length, opcode, dst_qpn, psn, rkey = struct.unpack('16s16sBBHHHHIII', chunk)
            src_ip = src_ip.decode('utf-8').strip('\x00')
            dst_ip = dst_ip.decode('utf-8').strip('\x00')
            print(f"sip:{src_ip} dip:{dst_ip} ecn:{ecn} sport:{sport} dport:{dport} udp length:{payload_length} opcode:{opcode} dst qpn:{dst_qpn} psn:{psn} rkey:{rkey}")

# 在线输出报文关键信息
def callback(pkt):
    global cnt
    if pkt.haslayer("UDP") and pkt["UDP"].dport == 4791:
        print_info(pkt, only_nak=args.NAK)
        if args.save:
            serialize_pkt(pkt, args.save)




# 离线分析报文
def analysis_pcap(pkts):
    ini_time = pkts[0].time
    t = 0
    bytes = 0
    for pkt in pkts:
        if pkt.haslayer("UDP") and pkt["UDP"].dport == 4791:
            # 记录吞吐率
            bytes = bytes + pkt["UDP"].len
            if pkt.time - ini_time - t > 1:
                bytes_record.append(bytes)
                bytes = 0
                t += 1
            print_info(pkt, only_nak=args.NAK)
            if args.save:
                serialize_pkt(pkt, args.save)
    bytes_record.append(bytes)

def phi(x, M):
    return x[:, None] ** np.arange(M + 1)


if __name__ == "__main__":
    filter_string = "udp"  # 此时测试的吞吐量是接收和发送之和

    parser = argparse.ArgumentParser(description='sniffRDMA')
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument('-r', type=str, help='read a pcap file')
    group1.add_argument('-dev', type=str, help='set the device.')
    parser.add_argument('-thp', type=str, help='measure the throughput')
    parser.add_argument('-save', type=str, help='save output to file')
    parser.add_argument('-load', type=str, help='load output from file')
    parser.add_argument('-NAK', action='store_true', help='output only NAK packets')

    args = parser.parse_args()
    if args.load is not None:
        deserialize_pkt(args.load)
    else:
        # 在线抓包
        if args.dev is not None:
            try:
                if args.thp is not None:  # 在线测量吞吐量
                    sched = BackgroundScheduler(timezone='MST')
                    sched.add_job(record_throughput, 'interval', id='1_second_job', seconds=1)
                    sched.start()
                    sniff(filter=filter_string, iface=args.dev, prn=throughput)
                else:
                    sniff(filter=filter_string, iface=args.dev, prn=callback)
            except KeyboardInterrupt:
                print('\nsniffRDMA stop')
        elif args.r is not None:  # 离线分析数据包
            pkts = rdpcap(args.r)
            analysis_pcap(pkts)

        print('sniffRDMA stop\n')
        if args.thp is not None:
            x = range(0, len(bytes_record))
            plt.plot(x, bytes_record)
            plt.xlabel('Time(s)')
            plt.ylabel('Bytes')
            plt.savefig(args.thp)
