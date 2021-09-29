#!usr/bin/python
import sys
import sockets
if len(sys.argv) !=3 :
	print"[*] Usage ./smtp-enum.py <ip> <user>"
	exit(0)
ip = sys.argv[1]
user = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connect = s.connect((ip,25))
banner = s.recv(1024)

print(banner)

s.send("VRFY " + user +'\r\n')
result = s.recv(1024)
print result
s.close()
