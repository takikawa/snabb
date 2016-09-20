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
    uint16_t count1;
    uint16_t tag2;
    uint16_t count2;
    uint16_t tag3;
    uint16_t count3;
    uint16_t tag4;
    uint16_t count4;
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

local connection_cache, address_cache
local block_threshold = 5

-- a very simple 32-bit cipher that's not meant for security
-- taken from http://stackoverflow.com/a/9718378/898073
--
-- probably better to use something like skip32 in the long run
local function encrypt(key, addr)
  local L = bit.rshift(addr, 16)
  local R = bit.band(addr, 0xFFFF)
  local S = 0x79b9
  local round

  for round = 0, 23 do
    local F_0 = bit.band(bit.bxor(bit.bxor(bit.rshift(R, 5),
                                           bit.lshift(R, 2))
                                  + bit.bxor(bit.rshift(R, 3),
                                             bit.lshift(R, 4)),
                                  bit.bxor(R, S) + bit.bxor(R, key)),
                         0xFFFF)
          F = bit.bxor(L, F_0)
          L = R
          R = F
          S = S + 0x79b9
          key = bit.bor(bit.rshift(key, 3), bit.lshift(key, 29))
  end

  local ciphertext = bit.bor(bit.lshift(R, 16), L)
  return bit.rshift(ciphertext, 16),
         bit.band(ciphertext, 0x0000FFFF)
end

function encrypt_test()
  local key = 0xf3cb8e14
  local data1 = 0xfd325ffa
  local data2 = 0x29ddecba

  -- FIXME: this should test the idx/tag split properly
  assert(encrypt(key, data1) == 1154796784)
  assert(encrypt(key, data2) == 1100185509)
end

-- look up an "outside" IP in the address cache
function Scanner:lookup_count(addr)
  local idx, tag = encrypt(time, addr)
  local cache_line = self.address_cache[idx]

  if tag == cache_line.tag1 then
    return cache_line.count1
  elseif tag == cache_line.tag2 then
    return cache_line.count2
  elseif tag == cache_line.tag3 then
    return cache_line.count3
  elseif tag == cache_line.tag4 then
    return cache_line.count4
  else
    -- either the initial value or an approximation if this
    -- entry was evicted at some point
    return 0
  end
end

-- set the count for a given "outside" IP in the
-- address cache to the given count
function Scanner:set_count(addr, count)
  local idx, tag = encrypt(time, addr)
  local cache_line = self.address_cache[idx]

  if tag == cache_line.tag1 then
    cache_line.count1 = count
  elseif tag == cache_line.tag2 then
    cache_line.count2 = count
  elseif tag == cache_line.tag3 then
    cache_line.count3 = count
  elseif tag == cache_line.tag4 then
    cache_line.count4 = count
  else
    -- must evict an entry now
    local min_idx = 1
    local min = cache_line.count1

    for i = 2, 4 do
      local cur = cache_line["count"..i]
      if count < min then
        min_idx = i
        min = cur
      end
    end

    cache_line["tag"..min_idx] = tag
    cache_line["count"..min_idx] = count
  end
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

local function rd16(offset)
   return ffi.cast("uint16_t*", offset)[0]
end
local function rd32(offset)
   return ffi.cast("uint32_t*", offset)[0]
end

local function print_ip(ip)
  print(string.format("%d.%d.%d.%d.",
                      bit.band(0x000000FF, bit.rshift(ip, 24)),
                      bit.band(0x000000FF, bit.rshift(ip, 16)),
                      bit.band(0x000000FF, bit.rshift(ip, 8)),
                      bit.band(0x000000FF, bit.rshift(ip, 0))))
end

-- Handle connections where the source is from "inside" wrt to
-- the scan suppression
function Scanner:inside(data, len, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))

  local port = 0
  if off_port ~= nil then
    port = lib.ntohs(rd16(data + off_port))
  end

  idx = hash(src_ip, dst_ip, port) % 1000000
  count = self:lookup_count(dst_ip)

  cache_entry = self.connection_cache[idx]
  if cache_entry.in_to_out ~= 1 then
    if cache_entry.out_to_in == 1 then
      self:set_count(dst_ip, count - 2)
    end
    cache_entry.in_to_out = 1
  end

  cache_entry.age = 0
  link.transmit(self.output.output, self.pkt)
end

-- Handle connections where the source is from "outside"
-- the scan suppression target
function Scanner:outside(data, len, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))

  local port = 0
  if off_port ~= nil then
    port = lib.ntohs(rd16(data + off_port))
  end

  idx = hash(src_ip, dst_ip, port) % 1000000

  cache_entry = self.connection_cache[idx]
  count = self:lookup_count(src_ip)
  print(string.format("count is %d", count))

  -- TODO: the code above this point is very similar between outside/inside
  --       so it should probably be abstracted
  if count < block_threshold then
    if cache_entry.out_to_in ~= 1 then
      if cache_entry.in_to_out == 1 then
        self:set_count(src_ip, count - 1)
        cache_entry.out_to_in = 1
      elseif false then
        -- TODO: make this condition a "hygiene drop"
        --       probably by detecting those conditions
        --       in the matcher and passing a flag
      else
        self:set_count(src_ip, count + 1)
        cache_entry.out_to_in = 1
      end
      cache_entry.in_to_out = 1
    end

    -- if not dropped ...
    cache_entry.age = 0
    link.transmit(self.output.output, self.pkt)
  -- i.e., above block threshold
  else
    if cache_entry.in_to_out == 1 then
      -- TODO: fix these dummy values to actual packet inspection
      local is_syn = false
      local is_udp = false
      if is_syn or is_udp then
        return packet.free(self.pkt)
      elseif cache_entry.out_to_in ~= 1 then
        self:set_count(src_ip, count - 1)
        cache_entry.out_to_in = 1
      end
      -- internal or old
      cache_entry.age = 0
      link.transmit(self.output.output, self.pkt)
    else
      return packet.free(self.pkt)
    end
  end
end

-- process_packet : InputPort OutputPort -> Void
function Scanner:process_packet(i, o)
  local pkt = link.receive(i)

  self.pkt = pkt

  self.matcher = pfm.compile([[
    match {
      -- TODO: what happens to the port argument when it's not TCP?
      ip and src net $inside_net and not dst net $inside_net => {
          -- TODO: it could be helpful to make the handler here the same in
          --       all cases, but pass flags around instead
          --       (in order to reduce code dup.)
          --       (but pfmatch doesn't let you do that)
          ip proto tcp => inside($src_addr_off, $dst_addr_off, $tcp_port_off)
          otherwise => inside($src_addr_off, $dst_addr_off)
        }
      ip and not src net $inside_net and dst net $inside_net => {
          ip proto tcp => outside($src_addr_off, $dst_addr_off, $tcp_port_off)
          otherwise => outside($src_addr_off, $dst_addr_off)
        }
    }]],
    -- TODO: parameterize this in a better way
    { subst = { src_addr_off = "&ip[12:4]",
                dst_addr_off = "&ip[16:4]",
                tcp_port_off = "&tcp[2:2]",
                inside_net = "10" } })

  self:matcher(pkt.data, pkt.length)
end
