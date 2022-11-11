import argparse
from scapy.all import sr1, sniff, conf
from scapy.layers.inet import IP, ICMP
from IPy import IP as IP2

ttl_set = {}

def test_spoof(att_pkt):
 try:
  count = 0
  if att_pkt.haslayer(IP):
   att_ip = att_pkt.getlayer(IP).src
   ip_ttl = str(att_pkt.ttl)
   print (count + '. Packet Received From: '+att_ip+' with TTL: ' + ip_ttl)
   count++
 except:
  pass
 
def check_TTL(chk_ip, chk_ttl):
    if IP2(chk_ip).iptype() == 'PRIVATE':
        return

    if chk_ip not in ttl_set:
        att_pkt = sr1(IP(dst=ipsrc) / ICMP(), retry=0, timeout=1, verbose=0)
        ttl_values[chk_ip] = att_pkt.ttl
  

def main():
 sniff(prn=test_spoof, store=0)

if __name__ == '__main__':
 main()
