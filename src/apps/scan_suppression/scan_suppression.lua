-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This app implements an approximate TRW-like scan detector
-- described in the Usenix Security paper
--   "Very Fast Containment of Scanning Worms"

module(..., package.seeall)

local ffi = require("ffi")
local C = ffi.C

local bit = require("bit")
local mm  = require("lib.hash.murmur")
local pfm = require("pf.match")
local lib = require("core.lib")

Scanner = {}

ffi.cdef[[
  typedef struct {
    uint8_t in_to_out : 1;
    uint8_t out_to_in : 1;
    uint8_t age : 6;
  } conn_cache_line_t;

  typedef struct {
    uint16_t tag1;
    uint16_t counter1;
    uint16_t tag2;
    uint16_t counter2;
    uint16_t tag3;
    uint16_t counter3;
    uint16_t tag4;
    uint16_t counter4;
  } addr_cache_line_t;
]]

local time = C.get_time_ns()
local murmur = mm.MurmurHash3_x64_128:new()

local function init_connection_cache()
  return ffi.new("conn_cache_line_t[1000000]")
end

local function init_address_cache()
  return ffi.new("addr_cache_line_t[1000000]")
end

-- hash : uint32 uint32 uint16 -> uint32
-- TODO: handle IPv6
local function hash(in_ip, out_ip, in_port)
  key = ffi.new("uint8_t [10]")
  ffi.cast("uint32_t*", key)[0] = in_ip
  ffi.cast("uint32_t*", key+4)[0] = out_ip
  ffi.cast("uint16_t*", key+8)[0] = in_port

  return murmur:hash(key, 10, time).u32[0]
end

-- constructor for the app object
function Scanner:new()
  local obj = { connection_cache = init_connection_cache(),
                address_cache = init_address_cache() }
  return setmetatable(obj, {__index = Scanner})
end

-- push packets through
function Scanner:push()
  local i = assert(self.input.input, "input port not found")
  local o = assert(self.output.output, "output port not found")

  while not link.empty(i) and not link.full(o) do
    self:process_packet(i, o)
  end
end

function rd16(offset)
   return ffi.cast("uint16_t*", offset)[0]
end
function rd32(offset)
   return ffi.cast("uint32_t*", offset)[0]
end
local to_uint32_buf = ffi.new('uint32_t[1]')
local function to_uint32(x)
   to_uint32_buf[0] = x
   return to_uint32_buf[0]
end
function htonl(s) return to_uint32(bit.bswap(s)) end

-- temporary
local function do_hash(data, len, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))
  local port = lib.ntohl(rd16(data + off_src))

  print(string.format("%d.%d.%d.%d.",
                      bit.band(0xFF, bit.rshift(src_ip, 128)),
                      bit.band(0xFF, bit.rshift(src_ip, 64)),
                      bit.band(0xFF, bit.rshift(src_ip, 32)),
                      bit.band(0xFF, bit.rshift(src_ip, 0))))

  print(hash(src_ip, dst_ip, port))
end

-- process_packet : InputPort OutputPort -> Void
function Scanner:process_packet(i, o)
  local pkt = link.receive(i)

  self.do_hash = do_hash

  --matcher = pfm.compile([[match {
  --  ip proto tcp => do_hash(&ip[12:4], &ip[16:4], &tcp[2:2])
  --}]], {source = true})
  self.matcher = pfm.compile[[match {
    ip proto tcp => do_hash(&ip[12:4], &ip[16:4], &tcp[2:2])
  }]]

  --print(matcher)
  self:matcher(pkt.data, pkt.length)

  -- do processing
  --link.transmit(o, p)
end
