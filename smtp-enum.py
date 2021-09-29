import socket
class SMTPUserEnumerator():
	def __init__(self, target, userlist, port=25, scantype="vrfy", mailfrom="root"):
		self.target = target
		self.userlist = userlist
		self.port = port
		self.scantype = scantype
		self.mailfrom = [mailfrom, True]	
		self.sock = None
		self.targetBanner = None
	
	def readUsers(self):
		with open(self.userlist, 'r') as file:
			users = file.read().strip().split('\n')
		self.userlist = users
		return
		
	def buildSock(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(self.target, self.port)
		self.sock = s
		banner = self.sock.recv(1024) [4::]
		if self.targetBanner == None:
			self.targetBanner = banner
		return
		
	def closeSock(self):
		self.sock.close()
		self.sock = None
		return
	def testScanType(self):
		if self.scantype == "vrfy":
			self.sock.send("VRFY \n")
			response = self.sock.recv(1024)
			self.sock.send("QUIT\n")
			self.closeSock()
			if "501" in response:
				return True
			else:
				return False
		elif self.scantype == "expn":
			self.sock.send("EXPN\n")
			response = self.sock.recv(1024)
			self.sock.send("QUIT\n")
			self.closeSock()
			if "502" in response:
				return False
			else:
				return True
		elif self.scantype == "rcpt":
			self.sock.send("MAIL FROM:%s \n" %(self.mailfrom[0]))
			self.sock.recv(1024)
			self.sock.send("RCPT TO/%s\n" %(self.mailfrom[0]))
			response = self.sock.recv(1024)
			self.sock.send("QUIT\n")
			self.closeSock()
			if ("250" in response) or ("550" in response):
				return True
			else:
				return False
		
	def probeTarget(self , user):
		if self.scantype == "vrfy":
			result = self.vrfyProbe(user)
		elif self.scantype == "expn":
			result = self.expnProbe(user)
		elif self.scantype == "rcpt":	
			result = self.rcptProbe(user)
		return result	

if __name__ == "__main__":
	import os
	import sys
	import argparse
	from datetime import datetime
	
	parser = argparse.ArgumentParser(description="SMTP User Enumeration Tool")
	parser.add_argument("-t", "--target", help="IP Adress of target SMTP Server" , action="store", dest="target", default=False)
	parser.add_argument("-p", "--port", help="Port number of target SMTP Server (default : 25)" , action="store", dest="port", default=25)
	parser.add_argument("-u", "--userlist", help="Path to wordlist of usernames to probe for" , action="store", dest="file", default=False)
	parser.add_argument("--mailfrom", help="change username used for MAIL FROM command (used in RCPT scan (default : root)" , action="store", dest="user", default="root")
	parser.add_argument("--scan-vrfy", help="Use VRFY Enumeration method" , action="store_true", dest="vrfy", default=False)
	parser.add_argument("--scan-expn", help="Use EXPN Enumeration method" , action="store_true", dest="expn", default=False)
	parser.add_argument("--scan-rcpt", help="Use RCPT Enumeration method" , action="store_true", dest="rcpt", default=False)
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(0)
	if not args.target:
	 	parser.error("No target IP adress given")
	 	sys.exit(1)
	try:
		socket.inet_aton(args.target)
	except socket.error:
		parser.error("Given target IP adress is invalid")
		sys.exit(1)
	try:
		if(int(args.port) < 0) and (int(args.port) > 65536 ):
	 		raise Exception
	except:
		parser.error("Given target port number is invalid")
		sys.exit(1)
	if not args.file:
		parser.erro("No wordlist given")
		sys.exit(1)
	elif not os.path.isfile(args.file):
		parser.error("Given wordlist does not exist")
		sys.exit(1)
	types = [args.vrfy, args.expn, args.rcpt]
	if (types.count(True) > 1) or (types.count(True) == 0):
		parser.error("Scan type selection invalid (choose one)")
		sys.exit(1)

if types[0]:
	scantype = "vrfy"
elif types[1]:
	scantype = "expn"
elif types[2]:
	scantype = "rcpt"

print "[*] %s scan chosen for use against %s:%s" %(scantype.upper(), args.target, str(args.port))
enumerator = SMTPUserEnumerator(args.target, args.file, port=int(args.port), scantype=scantype, mailfrom=args.user)
print "[*] checking for vulnerability to %s scan..." %(scantype.upper()),;sys.stdout.flush()
try:
	enumerator.buildSock()
	check = enumerator.testScanType()
	if check:
		print "[GOOD]"
	else:
		print "[BAD]"
		sys.exit(1)
except Exception:
	print "[FAIL]"
	sys.exit(1)
print "[*] Parsing list of users ...",;sys.stdount.flush()
try:
	enumerator.readUsers()
	print "[DONE]"
except:
	print "[FAIL]"
	sys.exit(1)	 
print "[*] Trying %s users ...\n" %(str(len(enumerator.userlist)))
startTime = datetime.now()
enumerator.buildSock()
print "Target banner: %s" %(enumerator.targetBanner)
for i in range(len(enumerator.userlist)):
	result = enumerator.probeTarget(enumerator.userlist[i])
	if result:
		print "Found: %s" %(enumerator.userlist[i])
enumerator.closeSock()
stopTime = datetime.now()

print "\n [*] Enumeration completed!"
print "[*] Duration: %s" %(str(stopTime-startTime))
 	
