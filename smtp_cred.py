from pprint import pprint
from dpkt.pcap import Reader
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP
from dpkt.tcp import TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR
from socket import inet_ntoa
import time
import base64
import itertools
import json
import numpy as np
import os
import datetime
import sys
reload(sys)  
sys.setdefaultencoding('Cp1252')




def PacketDiessector(pcap_path):

	def flagScanner(tcp):
		result = []
		if ( tcp.flags & TH_FIN ) != 0:
			result.append('fin')
		if ( tcp.flags & TH_SYN ) != 0:
			result.append('syn')
		if ( tcp.flags & TH_RST ) != 0:
			result.append('rst')
		if ( tcp.flags & TH_PUSH ) != 0:
			result.append('psh')
		if ( tcp.flags & TH_ACK ) != 0:
			result.append('ack')
		if ( tcp.flags & TH_URG ) != 0:
			result.append('urg')
		if ( tcp.flags & TH_ECE ) != 0:
			result.append('ece')
		if ( tcp.flags & TH_CWR ) != 0:
			result.append('cwr')
		return result

	print "[+] scanning : {}".format(pcap_path)
	sessions = {}
	d={}
	for ts, payload in Reader(open(pcap_path,'rb')):
		t, p = ts, payload
		eth = Ethernet(payload.__str__())
		packet = {}
		if eth.type == ETH_TYPE_IP:
			ip=eth.data
			packet['source_ip'] = inet_ntoa(ip.src)
			packet['destination_ip'] = inet_ntoa(ip.dst)
			if ip.p == IP_PROTO_TCP:
				tcp = ip.data
				if tcp.dport == 25:
					packet['source_port'] = tcp.sport
					packet['destination_port'] = tcp.dport
					packet['flags'] = flagScanner(tcp)
					packet['pkts_num'] = 1
					packet['pkts_size'] = tcp.data.__len__()
					packet['data'] = tcp.data
					uni_key = '{}:{}-->{}:{}'.format(packet['source_ip'],packet['source_port'],packet['destination_ip'],packet['destination_port'])
					
					if 'syn' in packet['flags']:
						if uni_key in sessions:
							del sessions[uni_key]
						sessions[uni_key] = packet
					elif 'fin' in packet['flags']:
						if uni_key in sessions:
							#sessions[uni_key]['flags'].extend(packet['flags'])
							#sessions[uni_key]['pkts_num']+=packet['pkts_num']
							#sessions[uni_key]['pkts_size']+=packet['pkts_size']
							sessions[uni_key]['source_port']+=packet['source_port']
							sessions[uni_key]['destination_port']+=packet['destination_port']
							sessions[uni_key]['data']+=packet['data']
							complete_session = sessions[uni_key]
							body=complete_session['data'] 
							port_source=complete_session['source_port'] 
							port_dest=complete_session['destination_port'] 
							sd=  str(inet_ntoa(ip.src))+':'+str(port_source)+'-->'+inet_ntoa(ip.dst) +': '+ str(port_dest) 
									
							if 'AUTH PLAIN' in complete_session['data']:
								pass
								j= complete_session['data'][complete_session['data'].find('AUTH PLAIN'):200]

								dump(j,sd)
								#print '*'*50

							if 'AUTH LOGIN' in complete_session['data']:
								pass		
								k= complete_session['data'][complete_session['data'].find('AUTH LOGIN'):200]
								#print k
								#print k
								dump(k,sd)
								#print '*'*50
								


							
					else:
						if uni_key in sessions:
							#sessions[uni_key]['flags'].extend(packet['flags'])
							#sessions[uni_key]['pkts_num']+=packet['pkts_num']
							#sessions[uni_key]['pkts_size']+=packet['pkts_size']
							sessions[uni_key]['source_port']+=packet['source_port']
							sessions[uni_key]['destination_port']+=packet['destination_port']
							sessions[uni_key]['data']+=packet['data']





def dump(data,sd):
	temp=data
	temp1=temp.strip()
	
	temp2=temp1.split('\r\n')[0:3]
	#print temp2[0:3]

	if 'AUTH LOGIN' in temp2:

		if  ":" not in temp2[0]:
			data = []
			for item in temp2:
				if ':' not in item:
					data.append(item)
				
			k= data[1:]
			if len(k)>=1:
				cred(k,sd)


def cred(k,sd):

	if len(k)==1:
		pass
	#	user_name = base64.b64decode(str(k))
	#	if user_name in k:
	#		del username
	#	print "user_name:",user_name
	#	m={key:value for key, value in zip(['username'],[user_name])}
		
		
	else:
		Password=base64.b64decode(k[1])
		UserName=base64.b64decode(k[0])
		if k>1:
			source_ip = sd.split('-->')[0].split(":")[0]
			source_port = sd.split('-->')[0].split(":")[1]
			dest_ip = sd.split('-->')[1].split(":")[0]
			dest_port = sd.split('-->')[1].split(":")[1]
			d={
			'UserName' :UserName.encode('utf-8'),
			'Password' : Password.encode('utf-8'),
			'Source_IP' : source_ip.encode('utf-8'),
			'Destination_IP' : dest_ip.encode('utf-8') ,
			'Source_Port' :  source_port.encode('utf-8') ,
			'Destination_Port' :(dest_port.strip()).encode('utf-8'),
			'Host': '',
			'Type':'SMTP'
			}
			
			print json.dumps(d)
    		if cred:
        		url_path = os.path.join(os.getcwd(),'smtp')
        		if not os.path.exists(url_path):
            	 	 os.makedirs(url_path)
        		f_name = 'ftp_data'+'_'+datetime.datetime.now().__str__().replace(' ', '_').replace(':', '-').replace('.', '-')+'.json'
        		with open(os.path.join(url_path,f_name),'w') as mu:mu.write(json.dumps([d], encoding='latin1'))
			










	
		
PacketDiessector('smp.pcap')










