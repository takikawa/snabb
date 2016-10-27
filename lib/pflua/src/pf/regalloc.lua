-- Implements register allocation for pflua's native backend
--
-- Register allocation operates on a post-SSA pflua IR form.
--
-- The result of register allocation is a table that describes
-- the max spills/number of stack slots needed and the registers
-- for all variables in each basic block.
--
--   { num_spilled = 1
--     v1 = 1, -- %rcx
--     v2 = 2, -- %rdx
--     v3 = { spill = 0 },
--     L4 = {
--            r1 = 0, -- %rax
--            r2 = 8, -- %r8
--          } }
--
-- The tables for each block have a metatable set to look up in
-- the outer table for v? variables.
--
-- Register numbers are based on DynASM's Rq() register mapping.
--
-- The following registers are reserved and not allocated:
--   * %rdi to store the packet pointer argument
--   * %rsi to store the length argument
--
-- The allocator should first prioritize using caller-save registers
--   * %rax, %rcx, %rdx, %r8-%r11
--
-- before using callee-save registers
--   * %rbx, %r12-%r15

module(...,package.seeall)

local utils = require('pf.utils')

-- ops that read a register and contribute to liveness
local read_ops = utils.set("cmp", "add", "add-3", "add-i", "add-i",
                           "mul", "mul-i")

-- Update the ends of intervals based on variable occurrences in
-- the "control" ast
local function find_live_in_control(label, control, intervals)
   -- the head of an ast is always an operation name, so skip
   for i = 2, #control do
      local ast_type = type(control[i])

      if ast_type == "string" then
	 for _, interval in ipairs(intervals) do
	    if control[i] == interval.name then
	       interval.finish = label
	    end
	 end
      elseif ast_type == "table" then
	 find_live_in_control(label, control[i], intervals)
      end
   end
end

-- The lack of loops and unique register names for each load
-- in the instruction IR makes finding live intervals easy.
--
-- A live interval is a table
--   { name = String, start = number, finish = number }
--
-- The start and finish fields are indices into the instruction
-- array
--
local function live_intervals(instrs)
   local len = { name = "len", start = 1, finish = 1 }
   local order = { len }
   local intervals = { len = len }

   for idx, instr in ipairs(instrs) do
      local itype = instr[1]

      -- movs and loads are the only instructions that result in
      -- new live intervals
      if itype == "load" or itype == "mov" then
         local name = instr[2]
	 local interval = { name = name,
			    start = idx,
			    finish = idx }

         intervals[name] = interval
         table.insert(order, interval)

         -- movs also read registers, so update endpoint
         if itype == "mov" then
            intervals[instr[3]].finish = idx
         end

      -- update liveness endpoint for instructions that read
      elseif read_ops[itype] then
         for i=2, #instr do
            if type(instr[i]) == "string" then
               intervals[instr[i]].finish = idx
            end
         end
      end
   end

   -- we need the resulting allocations to be ordered by starting
   -- point, so we emit the ordered sequence rather than the map
   return order
end

-- All available registers, tied to unix x64 ABI
local caller_regs = {0, 1, 2, 8, 9, 10, 11}
local callee_regs = {3, 12, 13, 14, 15}
local num_regs = #caller_regs + #callee_regs

local function is_free(seq, name)
   for _, val in ipairs(seq) do
      if val == name
   end
end

local function insert_free(seq, name)
end

-- Do register allocation with the given IR
function allocate(ir)
   local intervals = live_intervals(ir)
   local active = {}

   -- caller-save registers, use these first
   local free_caller = utils.dup(caller_regs)
   -- callee-save registers, if we have to
   local free_callee = utils.dup(callee_regs)

   local allocation = { "len" = 6 } -- %rsi

   local function expire_old(interval)
      for _, active_interval in pairs(active) do
         if active_interval.finish >= interval.start then
            return
         else
            local name = active_interval.name
            local reg = allocation[name]

            table.remove(active, active_interval)
            if caller_regs[allocation[name]] then
               insert_free(free_caller, reg)
            elseif callee_regs[allocation[name]] then
               free_callee(free_callee, name)
            else
               error("unknown register")
            end
         end
      end
   end

   for _, interval in pairs(intervals) do
      expire_old(active, allocation, interval)

      if #free_caller == 0 and #free_callee == 0 then
         -- TODO: do a spill
      elseif #free_caller == 0 then
         allocation[interval.name] = free_callee[1]
      else
         allocation[interval.name] = free_caller[1]
      end
   end

   return allocation
end

function selftest()
   local function test(instrs, expected)
      utils.assert_equals(expected, live_intervals(instrs))
   end

   -- part of `tcp`, see pf.selection
   local example_1 =
      { { "label", 0 },
        { "cmp", "len", 34 },
        { "cjmp", "<", 4 },
        { "label", 3 },
        { "load", "v1", 12, 2 },
        { "cmp", "v1", 8 },
        { "cjmp", "!=", 6 },
        { "label", 5 },
        { "load", "r1", 23, 1 },
        { "cmp", "r1", 6 },
        { "cjmp", "=", "true-label" },
        { "ret-false" },
        { "label", 6 },
        { "cmp", "len", 54 },
        { "cjmp", "<", 8 },
        { "label", 7 },
        { "cmp", "v1", 56710 },
        { "cjmp", "!=", 10 },
        { "label", 9 },
        { "load", "v2", 20, 1 },
        { "cmp", "v2", 6 },
        { "cjmp", "!=", 12 } }

   test(example_1,
        { { name = "len", start = 1, finish = 14 },
          { name = "v1", start = 5, finish = 17 },
          { name = "r1", start = 9, finish = 10 },
          { name = "v2", start = 20, finish = 21 } })
end
