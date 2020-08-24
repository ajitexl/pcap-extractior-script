#!/usr/bin/env python2

from os import geteuid, devnull
from scapy.all import *
from sys import exit
import binascii
import argparse
import signal
import json
import datetime

telnet_stream = {}


def pkt_parser(pkt):
   
    if pkt.haslayer(Raw):
        load = pkt[Raw].load

    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return
    # TCP
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):

        ack = str(pkt[TCP].ack)
        seq = str(pkt[TCP].seq)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)

        telnet_logins(src_ip_port, dst_ip_port, load, ack, seq)

def telnet_logins(src_ip_port, dst_ip_port, load, ack, seq):
   
    if src_ip_port in telnet_stream:
        # Do a utf decode in case the client sends telnet options before their username
        try:
            telnet_stream[src_ip_port] += load.decode('utf8')
            print telnet_stream
        except UnicodeDecodeError:
            pass

        # \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
        if '\r' in telnet_stream[src_ip_port] or '\n' in telnet_stream[src_ip_port]:
            telnet_split = telnet_stream[src_ip_port].split(' ', 1)
            cred_type = telnet_split[0]
            #print cred_type
       
            value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
        
            msg = 'Telnet %s: %s' % (cred_type, value)
            cred={key:value for key, value in zip([cred_type],[value])}


            ip={key:value for key, value in zip(['source_ip:source_port','destination_ip:destination_port','cred'],[src_ip_port,dst_ip_port,msg])}
            credential_data(ip)
            del telnet_stream[src_ip_port]
            
    if len(telnet_stream) > 100:
        telnet_stream.popitem(last=False)
    mod_load = load.lower().strip()
    if mod_load.endswith('username:') or mod_load.endswith('login:'):
        telnet_stream[dst_ip_port] = 'username '
    elif mod_load.endswith('password:'):
        telnet_stream[dst_ip_port] = 'password '


def credential_data(ip):
    print ip


    
    #print json.dumps((cred))
    if ip:
        url_path = os.path.join(os.getcwd(),'telnet')
        if not os.path.exists(url_path):
             os.makedirs(url_path)
        f_name = 'telnet'+'_'+datetime.datetime.now().__str__().replace(' ', '_').replace(':', '-').replace('.', '-')+'.json'
        with open(os.path.join(url_path,f_name),'w') as mu:mu.write(json.dumps(ip, encoding='latin1'))


def main(args):
   
    if args:
        try:
            for pkt in PcapReader(args):
                pkt_parser(pkt)
        except IOError:
            exit('[-] Could not open %s' % args)

    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')

       

if __name__ == "__main__":
   main(sys.argv[1])
