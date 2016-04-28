#!/usr/bin/python

import sys
import string
import pexpect
import socket
from errors import *

global OK, CRITICAL, ERROR, WARNING, INFO, DEBUG

def select_service (ip):
	try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            #Check for ssh port
            result = sock.connect_ex((ip,22))
	    if result == 0:
	        return "ssh"

            #Check for telnet port
            result = sock.connect_ex((ip,23))
	    if result == 0:
	        return "telnet"
	except:
		#Throw exception in the future
		#print msg
		print "connection failed"
		print sys.exc_info()

	print "There is not ssh or telnet to host."
	return (CRITICAL)

def run_commands( ip, user, pwd, commands, port=None, service=None, log=None, prompts=[] ):
	"""Execute the given command by telnet or ssh.

	Try to open a socket firt to an ssh port and if fails to a
	telnet port, an run the command
	"""
	
	try:
                output = []
		conn = None
                if service == None:
		    service = select_service ( ip )

                if port == None:
                    port = 23
                    if service == "ssh":
                        port = 22

		if service == "ssh":
			conn = pexpect.spawn ( "ssh", ["-o StrictHostKeyChecking=no", user+"@"+ip], logfile=log )
		elif service == "telnet":
			conn = pexpect.spawn ( "telnet " + ip, logfile=log )

		if service == None:
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

                for cmd in commands:
		    conn.expect( prompts )
		    conn.sendline(cmd)
                    output.append(conn.after)
                return output
	except:
		print "command execution failed"
		print sys.exc_info()
		return (ERROR)

#run_commands(ip, user, pwd, commands, prompts=[ ".*:.*\$" ] )
