#!/usr/bin/env python
import hashlib
import hmac
import sys

if len(sys.argv) < 4:
	print >>sys.stderr, "Usage: calchmac.py ALG PASS FILE [FILE [..]]"
	sys.exit(1)

algtbl = (("md5", hashlib.md5),
	  ("sha1", hashlib.sha1),
	  ("sha256", hashlib.sha256),
	  ("sha224", hashlib.sha224),
	  ("sha512", hashlib.sha512),
	  ("sha384", hashlib.sha384))


alg = sys.argv[1]
pwd = sys.argv[2]
#salt1 = salt + "\0\0\0\x01"
algo = None

for (anm, aob) in algtbl:
	if alg == anm:
		algo = aob
		break

if not algo:
	print >>sys.stderr, "Hash algorithm %s not found!" % alg
	sys.exit(2)

#hmf = open("HMACS.%s" % alg, "w")
for fnm in sys.argv[3:]:
	f = file(fnm, "rb")
	if not f:
		print >>sys.stderr, "Could not open %s" % fnm
		sys.exit(3)
	#print fnm
	fcont = f.read()
	hm = hmac.HMAC(pwd, fcont, algo)
	#print >>hmf, "%s *%s" % (hm.hexdigest(), fnm)
	print "%s *%s" %(hm.hexdigest(), fnm)

