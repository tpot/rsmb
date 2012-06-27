#!/usr/bin/ruby

require "rubygems"
require "socket"
require "hexdump"
require "ap"

def make_netbios(payload)
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

def parse_netbios(packet)

  length, payload = packet.unpack("Na*")

  {
    length: length,
    payload: payload
  }

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

# Connect

sock = TCPSocket.open("localhost", 445)

# Send negprot request

packet = make_netbios(make_smb(negprot_request))
puts packet.hexdump

sock.write(packet)

# Receive reply

response = sock.recv(4)
len = response.unpack("N")[0]

response += sock.read(len) 
puts response.hexdump

# Parse negprot response

ap parse_smb(parse_netbios(response)[:payload])
