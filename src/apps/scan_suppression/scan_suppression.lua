-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

-- This app implements an approximate TRW-like scan detector
-- described in the Usenix Security paper
--   "Very Fast Containment of Scanning Worms"

module(..., package.seeall)

local ffi = require("ffi")
local C = ffi.C

local app = require("core.app")
local bit = require("bit")
local mm  = require("lib.hash.murmur")
local pf  = require("pf")
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

-- "T" in paper, the count at which we start to block connections
local block_threshold = 5

-- These specify the minimum and maximum connection counts that are allowed.
-- A minimum is specified so that a "good" connection (more negative) that
-- turns "bad" can be detected (as it turns more positive) without too many
-- attempts.
--
-- The max lets offending machines eventually connect again when set at a
-- finite value.
local C_min = -5
local C_max = math.huge

-- These specify the decay rate of connection stats. D_miss is the rate at
-- which miss counts are decremented.
--local D_miss = 60
local D_miss = 1

-- the number of seconds to wait to increase connection age and to check
-- for the D_conn threshold
--
-- D_conn is the time it takes in "age" units for a connection to get
-- dropped from the table.
--local age_interval = 60
local age_interval = 1
local D_conn = 10

local time = C.get_time_ns()
local murmur = mm.MurmurHash3_x64_128:new()

local connection_cache_size = 1000000
local address_cache_size    = 1000000

-- whether to print debug messages
local debug = false

local function init_connection_cache()
   return ffi.new(string.format("conn_cache_line_t[%d]", connection_cache_size))
end

local function init_address_cache()
   return ffi.new(string.format("addr_cache_line_t[%d]", connection_cache_size))
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
  if not (count >= C_max or count <= C_min) then
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
      -- must evict an entry now, we'll evict the
      -- one with the most negative count
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
end

local hygiene_matcher =
  pf.compile_filter([[tcp[tcpflags] & (tcp-rst|tcp-fin) != 0
                      or (tcp[tcpflags] & tcp-syn != 0
                          and tcp[tcpflags] & tcp-ack != 0)]])

local syn_or_udp_matcher =
  pf.compile_filter([[ip proto udp or tcp[tcpflags] & tcp-syn != 0]])

-- constructor for the app object
function Scanner:new(conf)
  local obj = { connection_cache = init_connection_cache(),
                address_cache = init_address_cache() }

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
    { subst = { src_addr_off = "&ip[12:4]",
                dst_addr_off = "&ip[16:4]",
                tcp_port_off = "&tcp[2:2]",
                inside_net   = conf.scan_inside_network } })

  return setmetatable(obj, {__index = Scanner})
end

-- push packets through
function Scanner:push()
  local i = assert(self.input.input, "input port not found")
  local o = assert(self.output.output, "output port not found")

  -- every D_miss/age_interval do some checks
  local now = app.now()
  self.miss_timer = self.miss_timer or now
  self.age_timer  = self.age_timer or now

  if now - self.miss_timer >= D_miss then
     self:decrement_misses()
     self.miss_timer = now
  end
  if now - self.age_timer >= age_interval then
     self:increment_ages()
     self.age_timer = now
  end

  while not link.empty(i) and not link.full(o) do
    self:process_packet(i, o)
  end
end

-- the following two methods handle time-based housekeeping tasks for
-- maintaining the connection and address tables
function Scanner:decrement_misses()
   for i = 0, address_cache_size - 1 do
      local entry = self.address_cache[i]

      if (entry.count1 > 0) then
	 entry.count1 = entry.count1 - 1
      end
      if (entry.count2 > 0) then
	 entry.count2 = entry.count2 - 1
      end
      if (entry.count3 > 0) then
	 entry.count3 = entry.count3 - 1
      end
      if (entry.count4 > 0) then
	 entry.count4 = entry.count4 - 1
      end
   end
end

function Scanner:increment_ages()
   for i = 0, connection_cache_size - 1 do
      local entry = self.connection_cache[i]

      -- is an active connection entry?
      if entry.out_to_in or entry.in_to_out then
	 entry.age = entry.age + 1
      end

      if entry.age >= D_conn then
	 entry.out_to_in = 0
	 entry.in_to_out = 0
	 entry.age       = 0
      end
   end
end

local function rd16(offset)
   return ffi.cast("uint16_t*", offset)[0]
end
local function rd32(offset)
   return ffi.cast("uint32_t*", offset)[0]
end

local function format_ip(ip)
  return string.format("%d.%d.%d.%d",
                       bit.band(0x000000FF, bit.rshift(ip, 24)),
                       bit.band(0x000000FF, bit.rshift(ip, 16)),
                       bit.band(0x000000FF, bit.rshift(ip, 8)),
                       bit.band(0x000000FF, ip))
end

-- Helper function that abstracts some data extraction/lookup
-- in the inside/outside handlers
function Scanner:extract(data, off_src, off_dst, off_port)
  local src_ip = lib.ntohl(rd32(data + off_src))
  local dst_ip = lib.ntohl(rd32(data + off_dst))

  local port = 0
  if off_port ~= nil then
    port = lib.ntohs(rd16(data + off_port))
  end

  idx = hash(src_ip, dst_ip, port) % 1000000
  cache_entry = self.connection_cache[idx]

  return cache_entry, src_ip, dst_ip, port
end

-- Handle connections where the source is from "inside" wrt to
-- the scan suppression
function Scanner:inside(data, len, off_src, off_dst, off_port)
  local cache_entry, src_ip, dst_ip, port =
    self:extract(data, off_src, off_dst, off_port)

  count = self:lookup_count(dst_ip)

  if cache_entry.in_to_out ~= 1 then
    if cache_entry.out_to_in == 1 then
      -- previously a "miss" but now a "hit"
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
  local cache_entry, src_ip, dst_ip, port =
    self:extract(data, off_src, off_dst, off_port)

  count = self:lookup_count(src_ip)

  if count < block_threshold then
    if cache_entry.out_to_in ~= 1 then
      if cache_entry.in_to_out == 1 then
        self:set_count(src_ip, count - 1)
        cache_entry.out_to_in = 1
      elseif hygiene_matcher(self.pkt.data, self.pkt.length) then
	if debug then
	   print("blocked packet due to hygiene check")
	end
        return packet.free(self.pkt)
      else
        -- a potential "miss"
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
        if syn_or_udp_matcher(self.pkt.data, self.pkt.length) then
	   if debug then
	      print("blocked initial SYN/UDP packet for blocked host")
	   end
	   return packet.free(self.pkt)
	elseif cache_entry.out_to_in ~= 1 then
	   -- a "hit"
	   self:set_count(src_ip, count - 1)
	   cache_entry.out_to_in = 1
	end
	-- internal or old
	cache_entry.age = 0
	link.transmit(self.output.output, self.pkt)
     else
	if debug then
	   print(string.format("blocked packet from %s on port %d",
			       format_ip(src_ip), port))
	end
	return packet.free(self.pkt)
     end
  end
end

-- process_packet : InputPort OutputPort -> Void
function Scanner:process_packet(i, o)
  local pkt = link.receive(i)

  self.pkt = pkt

  self:matcher(pkt.data, pkt.length)
end
