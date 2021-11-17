from scapy.all import *
import sys, os

from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


def main(path):
   packets_by_ip = {}
   print("Loading pcap file...")
   packets = rdpcap(path)
   print("File loaded.")
   bots = {}
   not_bots = {}
   p_cnt = 0
   for p in packets:
      p_cnt += 1
      print("Parsing packet number {}/{}".format(p_cnt, len(packets)), end='\r')
      if p.haslayer(DNSQR):
         if p[IP].src not in packets_by_ip:
            packets_by_ip[p[IP].src] = {}
         if p[DNSQR].qname not in packets_by_ip[p[IP].src]:
            packets_by_ip[p[IP].src][p[DNSQR].qname] = []
         packets_by_ip[p[IP].src][p[DNSQR].qname].append(p)
   for ip in packets_by_ip:
      print("IP: {}".format(ip))
      for qname in packets_by_ip[ip]:
         dn_length = len(qname)
         p_num = len(packets_by_ip[ip][qname])
         print("\tQuery domain name: {}".format(qname))
         print("\t\tDomain name length: {}".format(dn_length))
         print("\t\tNumber of packets: {}".format(p_num))
         intervals = []
         for i in range(1, len(packets_by_ip[ip][qname])):
            diff = packets_by_ip[ip][qname][i].time - packets_by_ip[ip][qname][i-1].time
            diff = int(round(diff))
            if diff not in intervals:
               intervals.append(diff)
         intervals_num = len(intervals)
         print("\t\tRequests intervals ({}): {}".format(intervals_num, intervals))
         print("\t\t'botnet' present in domain name: {}".format(qname.find(b'botnet') != -1))
         print("\t\tStatistics:")
         if len(packets_by_ip[ip][qname]) > 1:
            stat_1 = 1.0 - intervals_num / (p_num - 1)
            if stat_1 > 0.95:
               if ip not in bots:
                  bots[ip] = list(packets_by_ip[ip].keys())
            print("\t\t\t1 - #intervals/(#packets-1): {}".format(stat_1))
         else:
            print("\t\t\t1 - #intervals/(#packets-1): cannot build this statistic with one packet")
      if ip not in bots:
         not_bots[ip] = list(packets_by_ip[ip].keys())
   print("Detected bots:")
   print(bots)
   fp_cnt = 0
   tp_cnt = 0
   for ip in bots:
      botnet_present = False
      for qname in bots[ip]:
         if qname.find(b'botnet') != -1:
            botnet_present = True
            break
      if not botnet_present:
         fp_cnt += 1
      else:
         tp_cnt += 1
   print("Not bots:")
   print(not_bots)
   fn_cnt = 0
   tn_cnt = 0
   for ip in not_bots:
      botnet_present = False
      for qname in not_bots[ip]:
         if qname.find(b'botnet') != -1:
            botnet_present = True
            break
      if botnet_present:
         fn_cnt += 1
      else:
         tn_cnt += 1
   print("Number of hosts: {}".format(len(packets_by_ip)))
   print("True positive: {} ({:0.2f}%)".format(tp_cnt, tp_cnt / (tp_cnt + fp_cnt) * 100.0))
   print("False positive: {} ({:0.2f}%)".format(fp_cnt, fp_cnt / (tp_cnt + fp_cnt) * 100.0))
   print("True negative: {} ({:0.2f}%)".format(tn_cnt, tn_cnt / (tn_cnt + fn_cnt) * 100.0))
   print("False negative: {} ({:0.2f}%)".format(fn_cnt, fn_cnt / (tn_cnt + fn_cnt) * 100.0))

if __name__ == "__main__":
   try:
      path = sys.argv[1]
   except:
      print("python3 detect_bots.py <path_to_pcap_file>")
      sys.exit(-1)
   if not os.path.isfile(path):
      print("Invalid file path!")
      sys.exit(-1)
   main(path)

