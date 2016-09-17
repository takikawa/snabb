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

local connection_cache, address_cache
local block_threshold = 5

local function encrypt(addr)
  -- TODO: implement
end

-- look up an "outside" IP in the address cache
local function lookup_count(addr)
  idx, tag = encrypt(addr)
  cache_line = address_cache[idx]

  if tag == cache_line.tag1 then
    return cache_line.count1
  else if tag == cache_line.tag2 then
    return cache_line.count2
  else if tag == cache_line.tag3 then
    return cache_line.count3
  else if tag == cache_line.tag4 then
    return cache_line.count4
  else
    -- either the initial value or an approximation if this
    -- entry was evicted at some point
    return 0
  end
end

-- set the count for a given "outside" IP in the
-- address cache to the given count
local function set_count(addr, count)
  idx, tag = encrypt(addr)
  cache_line = address_cache[idx]

  if tag == cache_line.tag1 then
    cache_line.count1 = count
  else if tag == cache_line.tag2 then
    cache_line.count2 = count
  else if tag == cache_line.tag3 then
    cache_line.count3 = count
  else if tag == cache_line.tag4 then
    cache_line.count4 = count
  else
    -- must evict an entry now
    local min_idx = 1
    local min = cache_line.count1

    for i = 2, i < 5 do
      local cur = cache_line["count"..i]
      if count < min then
        min_idx = i
        min = cur
      else
    end

    cache_line["tag"..min_idx] = tag
    cache_line["count"..min_idx] = count
  end
end

-- constructor for the app object
function Scanner:new()
  -- TODO: these really should be part of the object state, but because
  --       pfmatch doesn't pass 'self' around, it can't be part of the state yet
  connection_cache = init_connection_cache()
  address_cache = init_address_cache()
  local obj = { }
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
local function inside(data, len, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))

  local port = 0
  if off_port ~= nil then
    port = lib.ntohs(rd16(data + off_port))
  end

  idx = hash(src_ip, dst_ip, port) % 1000000

  -- TODO: pfmatch doesn't actually pass the 'self' parameter in its
  --       compiled matcher, which is why this doesn't access obj state
  cache_entry = connection_cache[idx]
  if cache_entry.in_to_out ~= 1 then
    if cache_entry.out_to_in == 1 then
      print("decrement count by two")
    cache_entry.in_to_out = 1
  end

  cache_entry.age = 0

  print("do forward packet")
end

-- Handle connections where the source is from "outside"
-- the scan suppression target
local function outside(data, len, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))

  local port = 0
  if off_port ~= nil then
    port = lib.ntohs(rd16(data + off_port))
  end

  idx = hash(src_ip, dst_ip, port) % 1000000

  cache_entry = connection_cache[idx]
  count = lookup_count(src_ip)

  -- TODO: the code above this point is very similar between outside/inside
  --       so it should probably be abstracted
  if count < block_threshold then
    if cache_entry.out_to_in ~= 1 then
      if cache_entry.in_to_out == 1 then
        print("decrement count by one")
        cache_entry.out_to_in = 1
      else if false then
        -- TODO: make this condition a "hygiene drop"
        --       probably by detecting those conditions
        --       in the matcher and passing a flag
      else
        print("increment count by one")
        cache_entry.out_to_in = 1
      end
      cache_entry.in_to_out = 1
    end

    -- if not dropped ...
    cache_entry.age = 0
    print("do forward packet")
  -- i.e., above block threshold
  else
    if cache_entry.in_to_out == 1 then
      if is_syn or is_udp then
        print("drop packet")
      else if cache_entry.out_to_in ~= 1 then
        print("decrement count by one")
        cache_entry.out_to_in = 1
      end
      -- internal or old
      cache_entry.age = 0
      print("do forward packet")
    else
      print("drop packet")
    end
  end
end

-- process_packet : InputPort OutputPort -> Void
function Scanner:process_packet(i, o)
  local pkt = link.receive(i)

  -- TODO: put these assignments in the constructor
  self.inside = inside
  self.outside = outside

  --matcher = pfm.compile([[match {
  --  ip proto tcp and ip src 10 => do_hash(&ip[12:4], &ip[16:4], &tcp[2:2])
  --}]], {source = true})
  --print(matcher)

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
                inside_net = "192" } })

  self:matcher(pkt.data, pkt.length)

  -- do processing
  --link.transmit(o, p)
end
