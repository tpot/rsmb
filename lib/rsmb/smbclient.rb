#!/usr/bin/ruby

require "rubygems"
require "socket"
require "hexdump"
require "ap"
require "rsmb/netbios"
require "rsmb/negprot"

def make_smb(header, smb)

  words = (smb.words || "")
  bytes = (smb.bytes || "")

  smb_packet = [

    # Header

    "\xffSMB", 					# protocol

    smb.command, 				# command
    header[:ntstatus], 				# status
    header[:flags], header[:flags2], 		# flags

    header[:pid] & 0xffff0000 >> 16,		# high pid
    "\x00\x00\x00\x00\x00\x00\x00\x00", 	# signature

    header[:tid],				# tid
    header[:pid] & 0xffff,			# low pid
    header[:uid],				# uid
    header[:mid], 				# mid

    # Payload
    
    words.length / 2, 			# word count
    words,					# parameter words

    bytes.length, 				# byte count
    bytes					# bytes

  ].pack("a4cVcvva8xxvvvvca*va*")

end

def parse_smb(packet)

  protocol, cmd, status, flags, flags2, pid_high, sig, tid, pid_low, \
	uid, mid, wct, payload = packet.unpack("a4cVcvva8xxvvvvCa*")

  words, bct, bytes = payload.unpack("a#{wct*2}va*")

  {
    protocol: protocol,
    cmd: cmd,
    status: status,
    flags: flags,
    flags2: flags2,
    pid: (pid_high << 16) & pid_low,
    tid: tid,
    uid: uid,
    mid: mid,
    wct: wct,
    words: words,
    bct: bct,
    bytes: bytes 
  } 

end

header  = { 
  ntstatus: 0x00000000,
  flags: 0x08,
  flags2: 0xc801,
  pid: 1,
  tid: 0xffff,
  uid: 0xffff,
  mid:0
}

# Connect

sock = TCPSocket.open("localhost", 445)

# Send negprot request

packet = make_netbios(make_smb(header, NegprotRequest.new))
puts packet.hexdump

sock.write(packet)

# Receive reply

response = sock.recv(4)
len = response.unpack("N")[0]

response += sock.read(len) 
puts response.hexdump

# Parse negprot response

smb = parse_smb(parse_netbios(response)[:payload])

ap NegprotResponse.new(smb[:words], smb[:bytes])
