#!/usr/bin/python

import sys
import string
#import ssh
import telnetlib
import pexpect
from errors import *

global OK, CRITICAL, ERROR, WARNING, INFO, DEBUG

#def select_protocol(ip):
#	try:
#		#socket.connect_ex return 0 on success so we must negate it
#		#in the if statement
#		if not ssh.connect_ex((ip,22)):
#			return "ssh"
#		elif not telnet.connect((ip,23)):
#			return "telnet"
#	except:
#		#Throw exception in the future
#		#print msg
#		print "connection failed"
#		print sys.exc_info()
#
#	print "There is not ssh or telnet to host."
#	return (CRITICAL)

def run_commands(ip, user, pwd):
	"""Execute the given command by telnet or ssh.

	Try to open a socket firt to an ssh port and if fails to a
	telnet port, an run the command
	"""
	
	try:
		conn = None
		#proto = select_protocol(ip)
		proto = "ssh"
		if proto == "ssh":
			conn = pexpect.spawn ("ssh", args=["-o StrictHostKeyChecking=no", user+"@"+ip], logfile=sys.stdout)
		elif proto == "telnet":
			conn = pexpect.spawn ('telnet '+ip)

		if proto == None:
			print "There is not spawn process."
			return (CRITICAL)
		i = 0
		loggedin = False
		while loggedin == False:
			index = conn.expect([".*user.*",".*ssw.*"])
			if index == 0:
				conn.sendline(user)
			if index == 1:
				conn.sendline(pwd)
				loggedin = True

			i += 1
			if i > 3:
				print "No logged in"
				return (ERROR)

		conn.expect(".*:.*\$")
		conn.sendline("ls -a")
		conn.expect(".*:.*\$")
		conn.sendline("exit")
	except:		
		print "command execution failed"
		print sys.exc_info()
		return (ERROR)

ip = sys.argv[1]
user = sys.argv[2]
pwd = sys.argv[3]

run_commands(ip,user,pwd)
quit()
