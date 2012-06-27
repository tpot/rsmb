#!/usr/bin/ruby

# Make a NetBIOS packet

def make_netbios(payload)
  [payload.length & 0x00ffffff, payload].pack("Na*")
end

# Parse a NetBIOS packet

def parse_netbios(packet)
  length, payload = packet.unpack("Na*")
  {
    length: length,
    payload: payload
  }
end
