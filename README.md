# sobnado ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Automated network pwn using EternalBlue that exploits vulnerable SMB protocols in the LAN. This project is inspired from Worawit's [MS17-010](https://github.com/worawit/MS17-010)

## Usage

Typically, the shellcode for the executable file you want to run is hardcoded for full process automation. However, I added the ability to generate a shellcode for variant EXEs using `shellcode/genshell.py`. The module uses Metasploit's `download_exec` payload to generate a raw shellcode, which then is appended to the compiled 32-bit kernel shellcode (you can modify the script accordingly for system architecture, however the 32-bit is a safer bet).  

The script can be compiled in a executable format using libraries such as `pyinstaller` or `py2exe`.

## Known Issues  

After the tool runs, the hosted binary will get executed, however, it may also crash `lsass.exe` (responsible for enforcing the security policy on the system) which results in a computer restart after 60 seconds.

## Disclaimer
```
[!] Legal disclaimer: Usage of this tool for attacking targets without
prior mutual consent is illegal. It is the end user's responsibility
to obey all applicable local, state and federal laws. I assume
no liability and are not responsible for any misuse or damage caused.
```
