#!/usr/bin/env python
#Copyright (c) 2008 Jeff Bryner
#python script to gather gmail artifacts from a pd process memory dump

#example: 
#
#on windows box, use pd from www.trapkit.de ala: 
#pd -p 1234> 1234.dump
#
#where 1234 is a running instance of IE
#
#on linux box do:
#strings -el 1234.dump> memorystrings.txt
#pdgmail -f memorystrings.txt
#
#It'll find what it can out of the memory image including contacts, emails, last acccess times, IP addresses etc. 

#This program is free software; you can redistribute it and/or modify it under
#the terms of the GNU General Public License as published by the Free Software
#Foundation; either version 2 of the License, or (at your option) any later
#version.

#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along with
#this program; if not, write to the Free Software Foundation, Inc.,
#59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


import sys
import os
import types
import struct
from time import ctime
import getopt
import array
import re


safestringre=re.compile('[\x80-\xFF]')
ipre=re.compile('(?:\d{1,3}\.){3}\d{1,3}')
gmailcontactre=re.compile('(?:\[\"ct.*\])')
gmailmere=re.compile('(?:\[\"me.*\])')
gmailmessagere=re.compile('(?:\[\"ms\".*\])',re.MULTILINE)
gmailmessagere2=re.compile('(?:\[\"mb\".*\])',re.MULTILINE)
gmaillastaccessre=re.compile('(?:\[\"la.*\])')

fromre=re.compile('(?:[Ff]rom\s.+\/)')

def safestring(badstring):
        """makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        return safestringre.sub(lambda c: 'char#%d;' % ord(c.group(0)),badstring)


def parseOptions():
	options = {'file'	:'',
		   'verbose'	: False,
		   'bodies'	: True
		  }
	helpstr = 'Usage: ' + sys.argv[0] + ' [OPTIONS]' + """\n
Options:
   -f, --file       the file to use (stdin if no file given)
   -b, --bodies	    don't look for message bodies (helpful if you're getting too many false positives on the mb regex)
   -h, --help	    prints this 
   -v,--verbose	    be verbose (prints filename, other junk)
   -V,--version     prints just the version info and exits.
   
This expects to be unleashed on the result of running strings -el on a pd dump from windows process memory. Anything other than that, your mileage will certainly vary.\n
\n
"""	
	optlist, args = getopt.getopt(sys.argv[1:], 'vhbf:V', ['help','file=','version','verbose','bodies'])
	#parse options.
	for o, a in optlist:
		if (o == '-h' or o == '--help'):
			print helpstr
			sys.exit()
		elif (o == '-v' or o == '--verbose'):
			options['verbose']=True			
		elif (o == '-b' or o == '--bodies'):
			options['bodies']=False
		elif (o == '-V' or o == '--version'):
			print "pdgmail version 0.2.0 Jeff Bryner"
			sys.exit()		
		else:	
			for option in options.keys():
				execcode = "if (o == '-%s' or o == '--%s'): options['%s'] = a" % (option[0], option, option)
				exec execcode

	return options


def gatherArtifacts():

	filedata=""
	gmailacctme=""
	
	if options["verbose"]:
		print "FileName: %s " % options["file"]
	try:
		if options["file"]!='':
			fileHandle = open(options["file"], mode='r')
			fileHandle.close()
	except IOError:
		sys.stderr.write('Cannot open file\n')
		sys.exit(1)


    #read in the stdin/file 
    	if options["file"] != '':
        	fp = open(options['file'], 'r')
		filedata = fp.read()
		fp.seek(0)

	#look for gmail contact records: 
	try:
		while 1:
		        if options["file"] != '':
        		        line = safestring(fp.readline())
		        else:
	        	        line = safestring(sys.stdin.readline())
				#we're reading stdin. Messages cross more than one line, so messily concat lines back into a filedata blob for use later.
				filedata +=line
		        if not line:
	        	    break
			    

			gmailcontacts=gmailcontactre.findall(line)
		        if len(gmailcontacts)>0:
				#we are handling a contact record, should look like this: ["ct","contactname","emailaddress@gmail.com",0,"3"]
				#I've no idea what the numbers are, the names we parse out neatly if possible
				for ct in gmailcontacts:
					try:
						#convert it to a list and print out the subsections
						ctList=[]
						ctList=ct.replace('[','').replace(']','').split(',')
						print "contact: name: %s email: %s" %(ctList[1],ctList[2])
					except:
						print "raw contact: " + line.strip()
			
			gmailmes=gmailmere.findall(line)
			if len(gmailmes)>0:
				#we are handling a "me" record, should look like this: ["me","someemail@gmail.com"]
				for me in gmailmes:
					try:
						#convert it to a list and print out the subsections
						meList=[]
						meList=me.replace('[','').replace(']','').split(',')
						print "gmail account: email: %s" %(meList[1])
						gmailacctme=str(me)
						if options["verbose"]:
							print "gmail me record:" + str(me)
					except:
						print "raw gmail account: " + line.strip()

			gmaillastaccesses=gmaillastaccessre.findall(line)
			if len(gmaillastaccesses)>0:
				#this line maybe a last access, they have at least one ip in them, so does this match? (some times they come in other lines of html which we don't parse)
				if len(ipre.findall(line))>0:
					for la in gmaillastaccesses:
						try:
							#convert it to a list and print out the subsections
							laAsList=[]
							laAsList=la.replace('[','').replace(']','').split(',')
							print "last access: %s from IP %s, most recent access %s from IP %s" %(laAsList[1],laAsList[3],ctime(float(laAsList[8])),laAsList[9])
						except:
							print"last access (can't parse it): " + str(la)
			
			
		#done with line by line proccessing
		#look for message headers, they can cross multiple lines:
		gmailmessageheaders=gmailmessagere.findall(filedata)
		#print repr(filedata)
		if len(gmailmessageheaders)>0:
			for mh in gmailmessageheaders:
				try:
					#looks like gmail is unicode encoded, rather than substitute all those chars, we'll use python's unicode support if possible
					umh=unicode(str(mh),'unicode-escape')
					print "message header: " + umh
				except:	
					#something amiss, dump what we've got
					print "message headers: " + str(gmailmessageheaders)

		#second attempt at message header (datapack type mb instead of ms)
		gmailmessageheaders2=gmailmessagere2.findall(filedata)
		if len(gmailmessageheaders2)>0:
			for mh in gmailmessageheaders2:
				try:
					#looks like gmail is unicode encoded, rather than substitute all those chars, we'll use python's unicode support if possible
					umh=unicode(str(mh),'unicode-escape')
					print "message header: " + umh
				except:	
					#something amiss, dump what we've got
					print "message headers: " + str(gmailmessageheaders2)

		if options["bodies"]:
			#try to piece together any message bodies, best guess is that they begin with datpack "ms" and end after multiple lines, in memory usually missing the ending brackets, 
			#example: ["ms","113b0d734737dec4","",   ....   ["me","someemail@gmail.com"]
			#so we look for the corresponding 'me' record after the "ms" datapack type.
			#first take at the regex:
			#messagebodyregex=r'\["ms.*?' + str(gmailacctme).replace('[','\[').replace(']','\]') 

			#2nd take to account for messy full memory dumps that tend to false positive on the above
			#find the ms datapack, and the ending "me" record with no more than 10k in between.
			messagebodyregex=r'((?:\["ms\",".{10,20}",""){1}.{200,10000}?(?:\[' + str(gmailacctme).replace('[','\[').replace(']','\]') + r'))'

			if options["verbose"]:
				sys.stderr.write('regex for messagebody is: ' +str(messagebodyregex) + '\n')

			gmailmessagebodyre=re.compile(messagebodyregex, re.IGNORECASE|re.DOTALL)
			gmailmessagebodies=gmailmessagebodyre.findall(filedata)
			if len(gmailmessagebodies)>0:
				for mb in gmailmessagebodies:
					try:
						#looks like gmail is unicode encoded, rather than substitute all those chars, we'll use python's unicode support if possible
						umb=unicode(str(mb),'unicode-escape')
						print "message body: " + umb
					except:
						#something amiss...dump what we've got.
						print "message bodies:" + str(gmailmessagebodies)
		

        except:
		sys.stderr.write("Error handling line:" + line)

		
def main():
	global options
	options = parseOptions()
	gatherArtifacts()

if __name__ == '__main__':
  main()
