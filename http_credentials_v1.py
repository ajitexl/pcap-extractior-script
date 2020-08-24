from pprint import pprint
from dpkt.pcap import Reader
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP
from dpkt.tcp import TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR
from socket import inet_ntoa
import time
import json
import base64
import os, datetime, re
import sys
import dpkt


def PacketDiessector(pcap_path):
    final = {}
    count = 0
    def parse_http(alll, sd):
        u, p = '', ''
        body = alll['data']
        user = ''
        passwd = ''
        method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE']
        matched_lines = [line for line in body.split('\n') if "Host:" in line]
        host = ''
        if matched_lines:
            host = matched_lines[0]
        userfields = ['login', 'user', 'user_name', 'email', 'username', '_username', 'userid', 'form_loginname',
                      'loginname',
                      'login_id', 'loginid', 'user_id', 'member', 'mailaddress', 'membername', 'login_username',
                      'login_email', 'loginusername', 'loginemail', 'sign-in']
        passfields = ['pass', 'password', '_password', 'passwd', 'login_password', 'loginpassword', 'form_pw',
                      'userpassword', 'login_password''passwort', 'passwrd']

        for login in userfields:
            login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
            if login_re:
                user = login_re.group()
        for passfield in passfields:
            pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
            if pass_re:
                passwd = pass_re.group()
        if user and passwd:
            u, p = user, passwd
        if 'Authorization: Basic' in body:
            k = body.split('\r\n')
            m = []
            for item in k:
                if "Authorization: Basic" in item:
                    user_id, password = base64.b64decode(str(item.split("Authorization: Basic"))).split(':')
                    u, p = user_id, password
                # print_credentials(user_id,password,sd,host)
        if u:
            if p:
                uni = "{}{}{}".format(sd, u, p)

                final[uni] = {
                    'UserName': u.strip(':').strip().split(';')[0],
                    'Password': p.strip(':').strip().split(';')[0],
                    'Source_IP': alll['source_ip'],
                    'Destination_IP': alll['destination_ip'],
                    'Source_Port': str(alll['source_port']),
                    'Destination_Port':str(alll['destination_port']),
                    'Host': host.strip('\r').strip('Host:').strip(),
                    'Type': 'HTTP'
                }


    def flagScanner(tcp):
        result = []
        if (tcp.flags & TH_FIN) != 0:
            result.append('fin')
        if (tcp.flags & TH_SYN) != 0:
            result.append('syn')
        if (tcp.flags & TH_RST) != 0:
            result.append('rst')
        if (tcp.flags & TH_PUSH) != 0:
            result.append('psh')
        if (tcp.flags & TH_ACK) != 0:
            result.append('ack')
        if (tcp.flags & TH_URG) != 0:
            result.append('urg')
        if (tcp.flags & TH_ECE) != 0:
            result.append('ece')
        if (tcp.flags & TH_CWR) != 0:
            result.append('cwr')
        return result



    "[+] scanning : {}".format(pcap_path)
    sessions = {}
    for ts, payload in Reader(open(pcap_path, "rb")):
        count+=1
        print '>>> packets scanned - ',count,'\r',
        t, p = ts, payload
        try:
            eth = Ethernet(payload.__str__())
            packet = {}
            if eth.type == ETH_TYPE_IP:
                ip = eth.data
                if type(ip) == str:
                    continue
                packet['source_ip'] = inet_ntoa(ip.src)
                packet['destination_ip'] = inet_ntoa(ip.dst)

                if ip.p == IP_PROTO_TCP:
                    tcp = ip.data
                    try:
                        if tcp.dport == 80 or tcp.sport == 80:
                            packet['source_port'] = tcp.sport
                            packet['destination_port'] = tcp.dport
                            packet['flags'] = flagScanner(tcp)
                            packet['pkts_num'] = 1
                            packet['pkts_size'] = tcp.data.__len__()
                            packet['data'] = tcp.data
                            uni_key = '{}:{}-->{}:{}'.format(packet['source_ip'], packet['source_port'],
                                                             packet['destination_ip'], packet['destination_port'])

                            if 'syn' in packet['flags']:
                                if uni_key in sessions:
                                    del sessions[uni_key]
                                sessions[uni_key] = packet

                            elif 'fin' in packet['flags']:
                                if uni_key in sessions:
                                    # sessions[uni_key]['flags'].extend(packet['flags'])
                                    # sessions[uni_key]['pkts_num']+=packet['pkts_num']
                                    # sessions[uni_key]['pkts_size']+=packet['pkts_size']
                                    sessions[uni_key]['source_port'] += packet['source_port']
                                    sessions[uni_key]['destination_port'] += packet['destination_port']
                                    sessions[uni_key]['data'] += packet['data']
                                    complete_session = sessions[uni_key]
                                    # bodyy=complete_session['data']
                                    port_source = complete_session['source_port']
                                    port_dest = complete_session['destination_port']
                                    parse_http(complete_session, uni_key)
                            else:
                                if uni_key in sessions:
                                    # sessions[uni_key]['flags'].extend(packet['flags'])
                                    # sessions[uni_key]['pkts_num']+=packet['pkts_num']
                                    # sessions[uni_key]['pkts_size']+=packet['pkts_size']
                                    sessions[uni_key]['source_port'] += packet['source_port']
                                    sessions[uni_key]['destination_port'] += packet['destination_port']
                                    sessions[uni_key]['data'] += packet['data']

                    except AttributeError:
                        continue
        except dpkt.NeedData:
            print 'courpt packet'

    for item in final:
        pprint(final[item])
        url_path = os.path.join(os.getcwd(), 'http_cred')
        if not os.path.exists(url_path): os.makedirs(url_path)
        f_name = 'http_cred' + '_' + datetime.datetime.now().__str__().replace(' ', '_').replace(':', '-').replace('.','-') + '.json'
        with open(os.path.join(url_path, f_name), 'w') as mu: mu.write(json.dumps([final[item]], encoding='latin1'))

if __name__ == '__main__':
    for root, dirs, files in os.walk('/media/user/my_dev/pcaps'):
        if files:
            for file in files:
                fpath = os.path.join(root, file)
                if os.path.exists(fpath):
                    if fpath.endswith('.pcap'):
                        PacketDiessector(fpath)

                    elif fpath.endswith('.net'):
                        if " " in fpath:
                            fpath = fpath.replace(" ", "\\ ")
                        respective_pcap_path = fpath.replace('.net', '.pcap')
                        # print "[+] converting : {}".format(fpath)
                        os.system('tshark -F pcap -r {} -w {}'.format(fpath, respective_pcap_path))
                        if os.path.exists(respective_pcap_path):
                            # print "[+] building : {}".format(respective_pcap_path)
                            PacketDiessector(respective_pcap_path)
                            os.remove(respective_pcap_path)
                        # print "[+] deleting : {}".format(respective_pcap_path)
                        else:
                            print
                            "X {}".format(fpath)

'''
def print_credentials(user,password,sd,host):


	source,destination=sd.split('-->')
	source_ip,source_port=source.split(':')
	destination_ip,destination_port=destination.split(':')
	key = sd + user.strip(':').strip().split(';')[0] +  password.strip(':').strip().split(';')[0] + host.strip('Host:').strip().replace('/r','')


	d={
	'UserName' : user.strip(':').strip().split(';')[0],
	'Password' : password.strip(':').strip().split(';')[0],
	'Source_IP' : source_ip.strip(':').strip(),
	'Destination_IP' : destination_ip.strip(':').strip(),
	'Source_Port' :  source_port.strip(':').strip(),
	'Destination_Port' : destination_port.strip(':').strip(),
	'Host': host.strip('Host:').strip().replace('/r',''),
	'Type':'HTTP'
	#'Url' : ''


	}
	unique[key] = d
	#print unique

	for key,value in  unique.items():
		if value not in unique.keys():
			result[key]=value
			print result[key]





	#print json.dumps((d))
	if dict:
		url_path = os.path.join(os.getcwd(),'http_cred')
	if not os.path.exists(url_path):
		os.makedirs(url_path)
        f_name = 'http_cred'+'_'+datetime.datetime.now().__str__().replace(' ', '_').replace(':', '-').replace('.', '-')+'.json'
        with open(os.path.join(url_path,f_name),'w') as mu:mu.write(json.dumps([d], encoding='latin1'))


'''



