#!/usr/bin/ruby

require "rubygems"
require "socket"
require "hexdump"

def netbios_encap(payload)
  [payload.length & 0x00ffffff, payload].pack("Na*")
end

def make_smb(header)

  smb_packet = [

    # Header

    "\xffSMB", 					# protocol

    header[:cmd], 				# command
    header[:ntstatus], 				# status
    header[:flags], header[:flags2], 		# flags

    header[:pid] & 0xffff0000 >> 16,		# high pid
    "\x00\x00\x00\x00\x00\x00\x00\x00", 	# signature

    header[:tid],				# tid
    header[:pid] & 0xffff,			# low pid
    header[:uid],				# uid
    header[:mid], 				# mid

    # Payload
    
    header[:words].length / 2, 				# word count
    header[:words],					# parameter words

    header[:bytes].length, 				# byte count
    header[:bytes]					# bytes

  ].pack("a4cVcvva8xxvvvvca*va*")

end

negprot_request = { 
  cmd: 0x72,
  ntstatus: 0x00000000,
  flags: 0x08,
  flags2: 0xc801,
  pid: 1,
  tid: 0xffff,
  uid: 0xffff,
  mid:0,
  bytes: "\x02NT LM 0.12\0",
  words: ""
}

packet = netbios_encap(make_smb(negprot_request))
puts packet.hexdump

sock = TCPSocket.open("localhost", 445)
sock.write(packet)
puts sock.recv(100).hexdump
