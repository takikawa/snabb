-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This module implements an app for MSS clamping

module(..., package.seeall)

local bit      = require("bit")
local ffi      = require("ffi")
local lib      = require("core.lib")
local link     = require("core.link")
local packet   = require("core.packet")
local datagram = require("lib.protocol.datagram")
local ether    = require("lib.protocol.ethernet")
local ipv4     = require("lib.protocol.ipv4")
local ipv6     = require("lib.protocol.ipv6")
local tcp      = require("lib.protocol.tcp")
local C        = ffi.C

local htonl, htons = lib.htonl, lib.htons

local IPV4_ETHERTYPE = 0x0800
local IPV6_ETHERTYPE = 0x86DD
local TCP_PROTOCOL_NUMBER = 0x06

MSSClamp = {}

function MSSClamp:new(config)
   local o = { mtu = config.mtu }
   return setmetatable(o, { __index = self })
end

function MSSClamp:push()
   local input = self.input.input
   assert(self.output.output, "missing output link")
   local output = self.output.output

   for i=1, link.nreadable(input) do
      local pkt = link.receive(input)
      self:clamp(pkt)
      link.transmit(output, pkt)
   end
end

local mss_payload_t = ffi.typeof([[
   struct {
      uint8_t kind;
      uint8_t length;
      uint32_t mss;
      uint16_t pad;
   } __attribute__((packed))
]])

local mss_payload = ffi.new(mss_payload_t)
mss_payload.kind = 0x02
mss_payload.length = 0x04
mss_payload.pad = 0x00

-- given a packet, if it's a TCP packet then adjust MSS to the app's config
-- otherwise don't touch it
function MSSClamp:clamp(pkt)
   local dgram = datagram:new(pkt, ether)
   local eth_h = dgram:parse_match()
   if (eth_h:type() == IPV4_ETHERTYPE or eth_h:type() == IPV6_ETHERTYPE) then
      local ip_h = dgram:parse_match()
      if (ip_h:protocol() == TCP_PROTOCOL_NUMBER) then
         local tcp_h = dgram:parse_match()
         if (tcp_h:syn() == 1) then
            mss_payload.mss = htonl(self.mtu);
            tcp_h:offset(tcp_h:offset() + ffi.sizeof(mss_payload_t))
            dgram:payload(ffi.cast("uint8_t*", mss_payload),
                          ffi.sizeof(mss_payload_t))
         end
      end
   end
end

function selftest()
   local dgram = datagram:new()
   local dgram2 = datagram:new()
   local dgram3 = datagram:new()
   local eth_h = ether:new({type=IPV4_ETHERTYPE})
   local ip_h = ipv4:new({dst=ipv4:pton("192.168.1.2"),
                          src=ipv4:pton("192.168.1.1"),
                          protocol=6})
   local tcp_syn_h = tcp:new({src_port=5000, dst_port=80, offset=5, syn=1})
   local tcp_non_syn_h = tcp:new({src_port=5000, dst_port=80, offset=5, syn=0})
   local tcp_mss_h = tcp:new({src_port=5000, dst_port=80,
                              offset=5+ffi.sizeof(mss_payload_t),
                              syn=1})

   -- put in a fairly standard MSS payload to test
   local payload = ffi.new(mss_payload_t)
   ffi.copy(payload, mss_payload, ffi.sizeof(mss_payload_t))
   payload.mss = htonl(1460)

   dgram:push(tcp_syn_h)
   dgram:push(ip_h)
   dgram:push(eth_h)
   dgram2:push(tcp_non_syn_h)
   dgram2:push(ip_h)
   dgram2:push(eth_h)
   dgram3:payload(payload, ffi.sizeof(mss_payload_t))
   dgram3:push(tcp_mss_h)
   dgram3:push(ip_h)
   dgram3:push(eth_h)

   local pkt = dgram:packet()
   local pkt2 = dgram2:packet()
   local pkt3 = dgram3:packet()
   local copy = packet.clone(pkt)
   local copy2 = packet.clone(pkt2)
   local copy3 = packet.clone(pkt3)

   local clamper = MSSClamp:new({mtu = 1300})
   clamper:clamp(copy)
   clamper:clamp(copy2)
   clamper:clamp(copy3)

   assert(not lib.equal(copy, pkt), "expected unequal pkts")
   assert(copy.length == pkt.length + ffi.sizeof(mss_payload),
          string.format("expected pkt size %d, got %d",
                        pkt.length + ffi.sizeof(mss_payload),
                        copy.length))
   assert(lib.equal(copy2, pkt2), "expected unchanged pkt")
   assert(not lib.equal(copy3, pkt3), "expected unequal pkts")
   assert(copy3.length == pkt3.length, "expected equal size pkts")
end
