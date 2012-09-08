#!/usr/bin/python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
"""
   Copyright (c) 2012 Sergio Castillo-Pérez

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
"""
# ------------------------------------------------------------------------------

import getopt
import signal
import socket
import select
import syslog
import sys
import os

# ------------------------------------------------------------------------------

VERSION       = "0.1.0"
SOCKBUFF_SIZE = 1500

# ------------------------------------------------------------------------------

def usage():
 
	print "Usage: " + sys.argv[0] + \
	      " [-d] -l port -i IP -r port [-a IP,IP,...] [-v]"
	print "\t-d	   --daemon	  Run as a daemon"
	print "\t-l	   --lport	  Local listen port"
	print "\t-i	   --ip		  Remote IP"
	print "\t-r	   --rport	  Remote port"
	print "\t-a	   --allowed-ips  Set of allowed source IPs"
	print "\t-s	   --syslog	  Send events to syslog"
	sys.exit(1)

# ------------------------------------------------------------------------------

def printlog(prio, str):
  
	if (slog):
		syslog.syslog(prio, str)
	else:
		if prio == syslog.LOG_INFO:
			sys.stdout.write(str + "\n")
			
		if prio == syslog.LOG_ERR:
			sys.stderr.write(str + "\n")

		sys.stdout.flush()
	
# ------------------------------------------------------------------------------

def param_verify():

	global daemon, lport, ip, rport, allowed_ips, slog

	lport = ip = rport = ""
	daemon = slog = False
	allowed_ips = ["ALL"]

	try:
		opts, args = getopt.getopt(sys.argv[1:], "dl:i:r:a:s", \
			["daemon", "lport=", "ip=", "rport=", "allowed-ips=",
			 "syslog"])

	except getopt.GetoptError:
		usage()

	for param, args in opts:
		if (param == "-d" or param == "--daemon"):
			daemon = True

		if (param == "-l" or param == "--lport"):
			lport = int(args)

		if (param == "-i" or param == "--ip"):
			ip = args

		if (param == "-r" or param == "--rport"):
			rport = int(args)

		if (param == "-a" or param == "--allowed-ips"):
			allowed_ips = args.split(',')

		if (param == "-s" or param == "--syslog"):
			slog = True

	if (lport == '' or ip == '' or rport == ''):
		usage()

# ------------------------------------------------------------------------------

def daemonize():

	try:
		pid = os.fork( )
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		msg = "Fork #1 failed: (%d) %s" % (e.errno, e.strerror)
		printlog(syslog.LOG_ERR, msg)
		sys.exit(1)

	os.chdir("/")
	os.umask(0)
	os.setsid()

	try:
		pid = os.fork( )
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		msg = "Fork #2 failed: (%d) %s" % (e.errno, e.strerror)
		printlog(syslog.LOG_ERR, msg)
		sys.exit(1)

# ------------------------------------------------------------------------------

def child_process(clientsock):

	try:
		remotesock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remotesock.connect((ip, rport))
	except:
		printlog(syslog.LOG_ERR, "Connection to remote IP problem!")
		clientsock.close()
		sys.exit(1)

	while True:
		sr, sw, se = select.select([clientsock, remotesock], [], [])

		for sock in sr:

			fromclient = ''
			fromserver = ''

			if (sock == clientsock):
				fromclient = clientsock.recv(SOCKBUFF_SIZE)
				remotesock.send(fromclient)
			else:
				fromserver = remotesock.recv(SOCKBUFF_SIZE)
				clientsock.send(fromserver)

		if (len(fromclient) <= 0 and len(fromserver) <= 0):
			break

	clientsock.close()
	remotesock.close()

	sys.exit(0)

# ------------------------------------------------------------------------------

def loop_bouncer():
  
	msg = "Waiting for connection at port " + str(lport)
	printlog(syslog.LOG_INFO, msg)
	
	try:
		localsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		localsock.bind(("", lport))
		localsock.listen(1)
	except:
		printlog(syslog.LOG_ERR,"Local socket problem!")
		sys.exit(1)

	# ----------------------------------------------------------------------

	signal.signal(signal.SIGCHLD, signal.SIG_IGN)

	while True:
		clientsock, addrinfo = localsock.accept()
		clientip = addrinfo[0]

		if (allowed_ips == ["ALL"] or (clientip in allowed_ips)):
		  	printlog(syslog.LOG_INFO, "Connection from " + clientip)

			pid = os.fork()
			if pid == 0:
				localsock.close()
				child_process(clientsock)
		else:
		  	printlog(syslog.LOG_INFO, "Connection from " + \
						  clientip + " refused!")
			clientsock.close()

# ------------------------------------------------------------------------------

if __name__ == "__main__":

	param_verify()
	if daemon:
		daemonize()

	printlog(syslog.LOG_INFO, "Starting PyBouncer v." + VERSION)
	loop_bouncer()

# ------------------------------------------------------------------------------
