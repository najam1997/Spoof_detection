from scapy.all import *

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

def main():
 sniff(prn=test_spoof, store=0)

if __name__ == '__main__':
 main()
