module(..., package.seeall)

local ffi = require("ffi")
local C = ffi.C
local S = require("syscall")
local bit = require("bit")
local binary_search = require("lib.binary_search")
local multi_copy = require("lib.multi_copy")
local bxor, bnot = bit.bxor, bit.bnot
local tobit, lshift, rshift = bit.tobit, bit.lshift, bit.rshift
local max, floor, ceil = math.max, math.floor, math.ceil

CTable = {}
LookupStreamer = {}

local HASH_MAX = 0xFFFFFFFF
local uint8_ptr_t = ffi.typeof('uint8_t*')
local uint16_ptr_t = ffi.typeof('uint16_t*')
local uint32_ptr_t = ffi.typeof('uint32_t*')
local uint64_ptr_t = ffi.typeof('uint64_t*')

local entry_types = {}
local function make_entry_type(key_type, value_type)
   local cache = entry_types[key_type]
   if cache then
      cache = cache[value_type]
      if cache then return cache end
   else
      entry_types[key_type] = {}
   end
   local ret = ffi.typeof([[struct {
         uint32_t hash;
         $ key;
         $ value;
      } __attribute__((packed))]],
      key_type,
      value_type)
   entry_types[key_type][value_type] = ret
   return ret
end

local function make_entries_type(entry_type)
   return ffi.typeof('$[?]', entry_type)
end

-- hash := [0,HASH_MAX); scale := size/HASH_MAX
local function hash_to_index(hash, scale)
   return floor(hash*scale)
end

local function make_equal_fn(key_type)
   local size = ffi.sizeof(key_type)
   local cast = ffi.cast
   if tonumber(ffi.new(key_type)) then
      return function (a, b)
         return a == b
      end
   elseif size == 2 then
      return function (a, b)
         return cast(uint16_ptr_t, a)[0] == cast(uint16_ptr_t, b)[0]
      end
   elseif size == 4 then
      return function (a, b)
         return cast(uint32_ptr_t, a)[0] == cast(uint32_ptr_t, b)[0]
      end
   elseif size == 6 then
      return function (a, b)
         return (cast(uint32_ptr_t, a)[0] == cast(uint32_ptr_t, b)[0] and
                 cast(uint16_ptr_t, a)[2] == cast(uint16_ptr_t, b)[2])
      end
   elseif size == 8 then
      return function (a, b)
         return cast(uint64_ptr_t, a)[0] == cast(uint64_ptr_t, b)[0]
      end
   else
      return function (a, b)
         return C.memcmp(a, b, size) == 0
      end
   end
end

local function set(...)
   local ret = {}
   for k, v in pairs({...}) do ret[v] = true end
   return ret
end

local function parse_params(params, required, optional)
   local ret = {}
   for k, _ in pairs(required) do
      if params[k] == nil then error('missing required option ' .. k) end
   end
   for k, v in pairs(params) do
      if not required[k] and optional[k] == nil then
         error('unrecognized option ' .. k)
      end
      ret[k] = v
   end
   for k, v in pairs(optional) do
      if ret[k] == nil then ret[k] = v end
   end
   return ret
end

-- FIXME: For now the value_type option is required, but in the future
-- we should allow for a nil value type to create a set instead of a
-- map.
local required_params = set('key_type', 'value_type')
local optional_params = {
   hash_fn = false,
   initial_size = 8,
   max_occupancy_rate = 0.9,
   min_occupancy_rate = 0.0
}

function new(params)
   local ctab = {}   
   local params = parse_params(params, required_params, optional_params)
   ctab.entry_type = make_entry_type(params.key_type, params.value_type)
   ctab.type = make_entries_type(ctab.entry_type)
   ctab.hash_fn = params.hash_fn or compute_hash_fn(params.key_type)
   ctab.equal_fn = make_equal_fn(params.key_type)
   ctab.size = 0
   ctab.max_displacement = 0
   ctab.occupancy = 0
   ctab.max_occupancy_rate = params.max_occupancy_rate
   ctab.min_occupancy_rate = params.min_occupancy_rate
   ctab = setmetatable(ctab, { __index = CTable })
   ctab:resize(params.initial_size)
   return ctab
end

-- FIXME: There should be a library to help allocate anonymous
-- hugepages, not this code.
local try_huge_pages = true
local huge_page_threshold = 1e6
local function calloc(t, count)
   local byte_size = ffi.sizeof(t) * count
   local mem, err
   if try_huge_pages and byte_size > huge_page_threshold then
      mem, err = S.mmap(nil, byte_size, 'read, write',
                        'private, anonymous, hugetlb')
      if not mem then
         print("hugetlb mmap failed ("..tostring(err)..'), falling back.')
         -- FIXME: Increase vm.nr_hugepages.  See
         -- core.memory.reserve_new_page().
      end
   end
   if not mem then
      mem, err = S.mmap(nil, byte_size, 'read, write',
                        'private, anonymous')
      if not mem then error("mmap failed: " .. tostring(err)) end
   end
   local ret = ffi.cast(ffi.typeof('$*', t), mem)
   ffi.gc(ret, function (ptr) S.munmap(ptr, byte_size) end)
   return ret, byte_size
end

function CTable:resize(size)
   assert(size >= (self.occupancy / self.max_occupancy_rate))
   local old_entries = self.entries
   local old_size = self.size
   local old_max_displacement = self.max_displacement

   -- Allocate double the requested number of entries to make sure there
   -- is sufficient displacement if all hashes map to the last bucket.
   self.entries, self.byte_size = calloc(self.entry_type, size * 2)
   self.size = size
   self.scale = self.size / HASH_MAX
   self.occupancy = 0
   self.max_displacement = 0
   self.occupancy_hi = ceil(self.size * self.max_occupancy_rate)
   self.occupancy_lo = floor(self.size * self.min_occupancy_rate)
   for i=0,self.size*2-1 do self.entries[i].hash = HASH_MAX end

   for i=0,old_size+old_max_displacement-1 do
      if old_entries[i].hash ~= HASH_MAX then
         self:insert(old_entries[i].hash, old_entries[i].key, old_entries[i].value)
      end
   end
end

function CTable:get_backing_size()
   return self.byte_size
end

local header_t = ffi.typeof[[
struct {
   uint32_t size;
   uint32_t occupancy;
   uint32_t max_displacement;
   double max_occupancy_rate;
   double min_occupancy_rate;
}
]]

function load(stream, params)
   local header = stream:read_ptr(header_t)
   local params_copy = {}
   for k,v in pairs(params) do params_copy[k] = v end
   params_copy.initial_size = header.size
   params_copy.min_occupancy_rate = header.min_occupancy_rate
   params_copy.max_occupancy_rate = header.max_occupancy_rate
   local ctab = new(params_copy)
   ctab.occupancy = header.occupancy
   ctab.max_displacement = header.max_displacement
   local entry_count = ctab.size + ctab.max_displacement

   -- Slurp the entries directly into the ctable's backing store.
   -- This ensures that the ctable is in hugepages.
   C.memcpy(ctab.entries,
            stream:read_array(ctab.entry_type, entry_count),
            ffi.sizeof(ctab.entry_type) * entry_count)

   return ctab
end

function CTable:save(stream)
   stream:write_ptr(header_t(self.size, self.occupancy, self.max_displacement,
                             self.max_occupancy_rate, self.min_occupancy_rate),
                    header_t)
   stream:write_array(self.entries,
                      self.entry_type,
                      self.size + self.max_displacement)
end

function CTable:insert(hash, key, value, updates_allowed)
   if self.occupancy + 1 > self.occupancy_hi then
      self:resize(self.size * 2)
   end

   local entries = self.entries
   local scale = self.scale
   -- local start_index = hash_to_index(hash, self.scale)
   local start_index = floor(hash*self.scale)
   local index = start_index

   -- Fast path.
   if entries[index].hash == HASH_MAX and updates_allowed ~= 'required' then
      self.occupancy = self.occupancy + 1
      entries[index].hash = hash
      entries[index].key = key
      entries[index].value = value
      return index
   end

   while entries[index].hash < hash do
      index = index + 1
   end

   while entries[index].hash == hash do
      if self.equal_fn(key, entries[index].key) then
         assert(updates_allowed, "key is already present in ctable")
         entries[index].key = key
         entries[index].value = value
         return index
      end
      index = index + 1
   end

   assert(updates_allowed ~= 'required', "key not found in ctable")

   self.max_displacement = max(self.max_displacement, index - start_index)

   if entries[index].hash ~= HASH_MAX then
      -- In a robin hood hash, we seek to spread the wealth around among
      -- the members of the table.  An entry that can be stored exactly
      -- where hash_to_index() maps it is a most wealthy entry.  The
      -- farther from that initial position, the less wealthy.  Here we
      -- have found an entry whose hash is greater than our hash,
      -- meaning it has travelled less far, so we steal its position,
      -- displacing it by one.  We might have to displace other entries
      -- as well.
      local empty = index;
      while entries[empty].hash ~= HASH_MAX do empty = empty + 1 end
      while empty > index do
         entries[empty] = entries[empty - 1]
         local displacement = empty - hash_to_index(entries[empty].hash, scale)
         self.max_displacement = max(self.max_displacement, displacement)
         empty = empty - 1;
      end
   end
           
   self.occupancy = self.occupancy + 1
   entries[index].hash = hash
   entries[index].key = key
   entries[index].value = value
   return index
end

function CTable:add(key, value, updates_allowed)
   local hash = self.hash_fn(key)
   assert(hash >= 0)
   assert(hash < HASH_MAX)
   return self:insert(hash, key, value, updates_allowed)
end

function CTable:update(key, value)
   return self:add(key, value, 'required')
end

function CTable:lookup_ptr(key)
   local hash = self.hash_fn(key)
   local entry = self.entries + hash_to_index(hash, self.scale)

   -- Fast path in case we find it directly.
   if hash == entry.hash and self.equal_fn(key, entry.key) then
      return entry
   end

   while entry.hash < hash do entry = entry + 1 end

   while entry.hash == hash do
      if self.equal_fn(key, entry.key) then return entry end
      -- Otherwise possibly a collision.
      entry = entry + 1
   end

   -- Not found.
   return nil
end

function CTable:lookup_and_copy(key, entry)
   local entry_ptr = self:lookup_ptr(key)
   if not entry_ptr then return false end
   ffi.copy(entry, entry_ptr, ffi.sizeof(entry))
   return true
end

function CTable:remove_ptr(entry)
   local scale = self.scale
   local index = entry - self.entries
   assert(index >= 0)
   assert(index < self.size + self.max_displacement)
   assert(entry.hash ~= HASH_MAX)

   self.occupancy = self.occupancy - 1
   entry.hash = HASH_MAX

   while true do
      entry = entry + 1
      index = index + 1
      if entry.hash == HASH_MAX then break end
      if hash_to_index(entry.hash, scale) == index then break end
      -- Give to the poor.
      entry[-1] = entry[0]
      entry.hash = HASH_MAX
   end

   if self.occupancy < self.occupancy_lo then
      self:resize(self.size / 2)
   end
end

-- FIXME: Does NOT shrink max_displacement
function CTable:remove(key, missing_allowed)
   local ptr = self:lookup_ptr(key)
   if not ptr then
      assert(missing_allowed, "key not found in ctable")
      return false
   end
   self:remove_ptr(ptr)
   return true
end

function CTable:make_lookup_streamer(stride)
   local res = {
      all_entries = self.entries,
      stride = stride,
      hash_fn = self.hash_fn,
      equal_fn = self.equal_fn,
      entries_per_lookup = self.max_displacement + 1,
      scale = self.scale,
      pointers = ffi.new('void*['..stride..']'),
      entries = self.type(stride),
      -- Binary search over N elements can return N if no entry was
      -- found that was greater than or equal to the key.  We would
      -- have to check the result of binary search to ensure that we
      -- are reading a value in bounds.  To avoid this, allocate one
      -- more entry.
      stream_entries = self.type(stride * (self.max_displacement + 1) + 1)
   }
   -- Give res.pointers sensible default values in case the first lookup
   -- doesn't fill the pointers vector.
   for i = 0, stride-1 do res.pointers[i] = self.entries end

   -- Initialize the stream_entries to HASH_MAX for sanity.
   for i = 0, stride * (self.max_displacement + 1) do
      res.stream_entries[i].hash = HASH_MAX
   end

   -- Compile multi-copy and binary-search procedures that are
   -- specialized for this table and this stride.
   local entry_size = ffi.sizeof(self.entry_type)
   res.multi_copy = multi_copy.gen(stride, res.entries_per_lookup * entry_size)
   res.binary_search = binary_search.gen(res.entries_per_lookup, self.entry_type)

   return setmetatable(res, { __index = LookupStreamer })
end

function LookupStreamer:stream()
   local stride = self.stride
   local entries = self.entries
   local pointers = self.pointers
   local stream_entries = self.stream_entries
   local entries_per_lookup = self.entries_per_lookup
   local equal_fn = self.equal_fn

   for i=0,stride-1 do
      local hash = self.hash_fn(entries[i].key)
      local index = hash_to_index(hash, self.scale)
      entries[i].hash = hash
      pointers[i] = self.all_entries + index
   end

   self.multi_copy(stream_entries, pointers)

   -- Copy results into entries.
   for i=0,stride-1 do
      local hash = entries[i].hash
      local index = i * entries_per_lookup
      local found = self.binary_search(stream_entries + index, hash)
      -- It could be that we read one beyond the ENTRIES_PER_LOOKUP
      -- entries allocated for this key; that's fine.  See note in
      -- make_lookup_streamer.
      if found.hash == hash then
         -- Direct hit?
         if equal_fn(found.key, entries[i].key) then
            entries[i].value = found.value
         else
            -- Mark this result as not found unless we prove
            -- otherwise.
            entries[i].hash = HASH_MAX

            -- Collision?
            found = found + 1
            while found.hash == hash do
               if equal_fn(found.key, entries[i].key) then
                  -- Yay!  Re-mark this result as found.
                  entries[i].hash = hash
                  entries[i].value = found.value
                  break
               end
               found = found + 1
            end
         end
      else
         -- Not found.
         entries[i].hash = HASH_MAX
      end
   end
end

function LookupStreamer:is_empty(i)
   assert(i >= 0 and i < self.stride)
   return self.entries[i].hash == HASH_MAX
end

function LookupStreamer:is_found(i)
   return not self:is_empty(i)
end

function CTable:selfcheck()
   local occupancy = 0
   local max_displacement = 0

   local function fail(expected, op, found, what, where)
      if where then where = 'at '..where..': ' else where = '' end
      error(where..what..' check: expected '..expected..op..'found '..found)
   end
   local function expect_eq(expected, found, what, where)
      if expected ~= found then fail(expected, '==', found, what, where) end
   end
   local function expect_le(expected, found, what, where)
      if expected > found then fail(expected, '<=', found, what, where) end
   end

   local prev = 0
   for i = 0,self.size+self.max_displacement-1 do
      local entry = self.entries[i]
      local hash = entry.hash
      if hash ~= 0xffffffff then
         expect_eq(self.hash_fn(entry.key), hash, 'hash', i)
         local index = hash_to_index(hash, self.scale)
         if prev == 0xffffffff then
            expect_eq(index, i, 'undisplaced index', i)
         else
            expect_le(prev, hash, 'displaced hash', i)
         end
         occupancy = occupancy + 1
         max_displacement = max(max_displacement, i - index)
      end
      prev = hash
   end

   expect_eq(occupancy, self.occupancy, 'occupancy')
   -- Compare using <= because remove_at doesn't update max_displacement.
   expect_le(max_displacement, self.max_displacement, 'max_displacement')
end

function CTable:dump()
   local function dump_one(index)
      io.write(index..':')
      local entry = self.entries[index]
      if (entry.hash == HASH_MAX) then
         io.write('\n')
      else
         local distance = index - hash_to_index(entry.hash, self.scale)
         io.write(' hash: '..entry.hash..' (distance: '..distance..')\n')
         io.write('    key: '..tostring(entry.key)..'\n')
         io.write('  value: '..tostring(entry.value)..'\n')
      end
   end
   for index=0,self.size-1+self.max_displacement do dump_one(index) end
end

function CTable:iterate()
   local max_entry = self.entries + self.size + self.max_displacement
   local function next_entry(max_entry, entry)
      while true do
         entry = entry + 1
         if entry >= max_entry then return nil end
         if entry.hash ~= HASH_MAX then return entry end
      end
   end
   return next_entry, max_entry, self.entries - 1
end

-- One of Bob Jenkins' hashes from
-- http://burtleburtle.net/bob/hash/integer.html.  It's about twice as
-- fast as MurmurHash3_x86_32 and seems to do just as good a job --
-- tables using this hash function seem to have the same max
-- displacement as tables using the murmur hash.
--
-- TODO: Switch to a hash function with good security properties,
-- perhaps by using the DynASM support for AES.
local uint32_cast = ffi.new('uint32_t[1]')
function hash_32(i32)
   i32 = tobit(i32)
   i32 = i32 + bnot(lshift(i32, 15))
   i32 = bxor(i32, (rshift(i32, 10)))
   i32 = i32 + lshift(i32, 3)
   i32 = bxor(i32, rshift(i32, 6))
   i32 = i32 + bnot(lshift(i32, 11))
   i32 = bxor(i32, rshift(i32, 16))

   -- Unset the low bit, to distinguish valid hashes from HASH_MAX.
   i32 = lshift(i32, 1)

   -- Project result to u32 range.
   uint32_cast[0] = i32
   return uint32_cast[0]
end

local cast = ffi.cast
function hashv_32(key)
   return hash_32(cast(uint32_ptr_t, key)[0])
end

function hashv_48(key)
   local hi = cast(uint32_ptr_t, key)[0]
   local lo = cast(uint16_ptr_t, key)[2]
   -- Extend lo to the upper half too so that the hash function isn't
   -- spreading around needless zeroes.
   lo = bor(lo, lshift(lo, 16))
   return hash_32(bxor(hi, hash_32(lo)))
end

function hashv_64(key)
   local hi = cast(uint32_ptr_t, key)[0]
   local lo = cast(uint32_ptr_t, key)[1]
   return hash_32(bxor(hi, hash_32(lo)))
end

local hash_fns_by_size = { [4]=hashv_32, [8]=hashv_64 }
function compute_hash_fn(ctype)
   local size = ffi.sizeof(ctype)
   if not hash_fns_by_size[size] then
      hash_fns_by_size[size] = function(key)
         local h = 0
         local words = cast(uint32_ptr_t, key)
         local bytes = cast(uint8_ptr_t, key)
         for i=0,size/4-1 do h = hash_32(bxor(h, words[i])) end
         for i=1,size%4 do h = hash_32(bxor(h, bytes[size-i])) end
         return h
      end
   end
   return hash_fns_by_size[size]
end

function selftest()
   print("selftest: ctable")

   -- 32-byte entries
   local occupancy = 2e6
   local params = {
      key_type = ffi.typeof('uint32_t'),
      value_type = ffi.typeof('int32_t[6]'),
      hash_fn = hash_32,
      max_occupancy_rate = 0.4,
      initial_size = ceil(occupancy / 0.4)
   }
   local ctab = new(params)
   ctab:resize(occupancy / 0.4 + 1)

   -- Fill with i -> { bnot(i), ... }.
   local v = ffi.new('int32_t[6]');
   for i = 1,occupancy do
      for j=0,5 do v[j] = bnot(i) end
      ctab:add(i, v)
   end

   for i=1,2 do
      -- In this case we know max_displacement is 8.  Assert here so that
      -- we can detect any future deviation or regression.
      assert(ctab.max_displacement == 8)

      ctab:selfcheck()

      for i = 1, occupancy do
         local value = ctab:lookup_ptr(i).value[0]
         assert(value == bnot(i))
      end
      ctab:selfcheck()

      -- Incrementing by 31 instead of 1 just to save test time.
      do
         local entry = ctab.entry_type()
         for i = 1, occupancy, 31 do
            assert(ctab:lookup_and_copy(i, entry))
            assert(entry.key == i)
            assert(entry.value[0] == bnot(i))
            ctab:remove(entry.key)
            assert(ctab:lookup_ptr(i) == nil)
            ctab:add(entry.key, entry.value)
            assert(ctab:lookup_ptr(i).value[0] == bnot(i))
         end
      end

      local iterated = 0
      for entry in ctab:iterate() do iterated = iterated + 1 end
      assert(iterated == occupancy)

      -- Save the table out to disk, reload it, and run the same
      -- checks.
      local tmp = os.tmpname()
      do
         local file = io.open(tmp, 'wb')
         local function write(ptr, size)
            file:write(ffi.string(ptr, size))
         end
         local stream = {}
         function stream:write_ptr(ptr, type)
            assert(ffi.sizeof(ptr) == ffi.sizeof(type))
            write(ptr, ffi.sizeof(type))
         end
         function stream:write_array(ptr, type, count)
            write(ptr, ffi.sizeof(type) * count)
         end
         ctab:save(stream)
         file:close()
      end
      do
         local file = io.open(tmp, 'rb')
         local function read(size)
            return ffi.new('uint8_t[?]', size, file:read(size))
         end
         local stream = {}
         function stream:read_ptr(type)
            return ffi.cast(ffi.typeof('$*', type), read(ffi.sizeof(type)))
         end
         function stream:read_array(type, count)
            return ffi.cast(ffi.typeof('$*', type),
                            read(ffi.sizeof(type) * count))
         end
         ctab = load(stream, params)
         file:close()
      end         
      os.remove(tmp)
   end

   -- OK, all looking good with the normal interfaces; let's check out
   -- streaming lookup.
   local stride = 1
   repeat
      local streamer = ctab:make_lookup_streamer(stride)
      for i = 1, occupancy, stride do
         local n = math.min(stride, occupancy-i+1)
         for j = 0, n-1 do
            streamer.entries[j].key = i + j
         end
         streamer:stream()
         for j = 0, n-1 do
            assert(streamer:is_found(j))
            local value = streamer.entries[j].value[0]
            assert(value == bnot(i + j))
         end
      end
      stride = stride * 2
   until stride > 256

   -- A check that our equality functions work as intended.
   local numbers_equal = make_equal_fn(ffi.typeof('int'))
   assert(numbers_equal(1,1))
   assert(not numbers_equal(1,2))

   local function check_bytes_equal(type, a, b)
      local equal_fn = make_equal_fn(type)
      local hash_fn = compute_hash_fn(type)
      assert(equal_fn(ffi.new(type, a), ffi.new(type, a)))
      assert(not equal_fn(ffi.new(type, a), ffi.new(type, b)))
      assert(hash_fn(ffi.new(type, a)) == hash_fn(ffi.new(type, a)))
      assert(hash_fn(ffi.new(type, a)) ~= hash_fn(ffi.new(type, b)))
   end
   check_bytes_equal(ffi.typeof('uint16_t[1]'), {1}, {2})         -- 2 byte
   check_bytes_equal(ffi.typeof('uint32_t[1]'), {1}, {2})         -- 4 byte
   check_bytes_equal(ffi.typeof('uint16_t[3]'), {1,1,1}, {1,1,2}) -- 6 byte
   check_bytes_equal(ffi.typeof('uint32_t[2]'), {1,1}, {1,2})     -- 8 byte
   check_bytes_equal(ffi.typeof('uint32_t[3]'), {1,1,1}, {1,1,2}) -- 12 byte

   -- Check keys with computed hash functions inserted into a table
   -- (this tests a bug in which the hash function was reading bogus data
   --  off the end of the struct)
   ffi.cdef[[struct point { uint32_t x; uint8_t y; } __attribute__((packed));]]

   local params = {
      key_type = ffi.typeof('struct point'),
      value_type = ffi.typeof('uint32_t'),
      hash_fn = compute_hash_fn('struct point'),
      max_occupancy_rate = 0.4,
      initial_size = ceil(occupancy / 0.4)
   }
   local ctab = new(params)

   for i=1, occupancy - 1 do
      local pt = ffi.new("struct point")
      pt.x = i; pt.y = 1;
      ctab:add(pt, 42ULL)
   end
   ctab:selfcheck()

   print("selftest: ok")
end
