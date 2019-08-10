#!/usr/bin/ruby

require 'rubygems'
require 'openssl'
require 'base64'

a = ARGV[0]
if (a.nil? or a.empty?)
	print "Encrypted data is not defined\n"
 	print "Usage : gpp-decrypt <value-to-decrypt>\n"
else
	def decrypt(a)
	  	padding = "=" * (4 - (a.length % 4))
	  	passwrd = "#{a}#{padding}"
	  	decoded = Base64.decode64(passwrd)

	  	key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
	  	aes = OpenSSL::Cipher.new("AES-256-CBC")
	  	aes.decrypt
	  	aes.key = key
	  	
	  	text = aes.update(decoded)
	  	text << aes.final
	  	pass = text.unpack('v*').pack('C*')

		return pass
	end

	blah = decrypt(a)
	puts blah
end
