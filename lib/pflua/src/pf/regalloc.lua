-- Implements register allocation for pflua's native backend
--
-- Register allocation operates on a post-SSA pflua IR form.
--
-- The result of register allocation is a table mapping variables
-- to register numbers. e.g.,
--
--   { v1 = 1, -- %rcx
--     v2 = 2, -- %rdx
--     v3 = { spill = 0 },
--     num_spilled = 1 }
--
-- where a spill table entry means to spill to the stack at the
-- given slot. The num_spilled entry indicates the number of spilled
-- variables.
--
-- Register numbers are based on DynASM's Rq() register mapping.
--
-- The following registers are reserved and not allocated:
--   * %rax for arithmetic expression computations
--   * %rdi to store the packet pointer argument
--   * %rsi to store the length argument
--
-- The allocator should first prioritize using caller-save registers
--   * %rcx, %rdx, %r8-%r11
--
-- before using callee-save registers
--   * %rbx, %r12-%r15
--
-- We conduct a simple allocation in which variables
-- have a single live range with no holes, which should work well
-- since the IR is so constrained.

module(...,package.seeall)

-- Update the ends of intervals based on variable occurrences in
-- the "control" ast
local function find_live_in_control(block_num, control, intervals)
   -- the head of an ast is always an operation name, so skip
   for i = 2, #control do
      local ast_type = type(control[i])

      if ast_type == "string" then
	 for _, interval in ipairs(intervals) do
	    if control[i] == interval.name then
	       interval.finish = block_num
	    end
	 end
      elseif ast_type == "table" then
	 find_live_in_control(block_num, control[i], intervals)
      end
   end
end

-- Given an SSA IR, compute the linear scan live intervals
-- This is very easy with our loop-less SSA representation since
-- the live interval simply starts at first occurrence of a
-- "bindings" for a variable and ends at the last reference.
--
-- A live interval is a table
--   { name = String, start = Num, finish = Num }
--
-- The IR is implicitly numbered by the array indices in
-- "blocks" which corresponds to depth-first order.
--
local function compute_live_intervals(ssa)
   local live_intervals = {}
   local blocks = ssa[3]

   for i = 2, #blocks do
      local bindings = blocks[i][3]
      local live = {}

      for j = 2, #bindings do
	 local interval = { name = bindings[j][1], start = i-1, finish = nil }
	 table.insert(live_intervals, interval)
      end

      find_live_in_control(i-1, blocks[i][4], live_intervals)
   end

   return live_intervals
end

-- Do register allocation with the given IR
function allocate_registers(ssa)
   local intervals = compute_live_intervals(ssa)
   local allocation = {}

   -- TODO: for now, spill all variables
   for idx, interval in ipairs(intervals) do
      allocation[interval.name] = { spill = idx - 1 }
   end

   allocation.num_spilled = #intervals

   return allocation
end

function selftest()
   -- "ip"
   local example_1 =
      { "ssa",
	{ "start", "L1" },
	{ "blocks",
	  { "block",
	    { "label", "L1" },
	    { "bindings" },
	    { "control",
	      { "if", { ">=", "len", 14 }, "L4", "L5" } } },
	  { "block",
	    { "label", "L4" },
	    { "bindings" },
	    { "control",
	      { "return",
		{ "=", { "[]", 12, 2 }, 8 } } } },
	  { "block",
	    { "label", "L5" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } } } }

   assert(#compute_live_intervals(example_1) == 0)

   local example_2 =
      { "ssa",
	{ "start", "L1" },
	{ "blocks",
	  { "block",
	    { "label", "L1" },
	    { "bindings" },
	    { "control", { "if", { ">=", "len", 34 }, "L4", "L5" } } },
	  { "block",
	    { "label", "L4" },
	    { "bindings", { "v1", { "[]", 12, 2 } } },
	    { "control",
	      { "if", { "=", "v1", 8 }, "L6", "L7" } } },
	  { "block",
	    { "label", "L6" },
	    { "bindings" },
	    { "control", { "return", { "=", { "[]", 23, 1 }, 6 } } } },
	  { "block",
	    { "label", "L7" },
	    { "bindings" },
	    { "control", { "if", { ">=", "len", 54 }, "L8", "L9" } } },
	  { "block",
	    { "label", "L8" },
	    { "bindings" },
	    { "control", { "if", { "=", "v1", 56710 }, "L10", "L11" } } },
	  { "block",
	    { "label", "L10" },
	    { "bindings", { "v2", { "[]", 20, 1 } } },
	    { "control", { "if", { "=", "v2", 6 }, "L12", "L13" } } },
	  { "block",
	    { "label", "L12" },
	    { "bindings" },
	    { "control", { "return", { "true" } } } },
	  { "block",
	    { "label", "L13" },
	    { "bindings" },
	    { "control", { "if", { ">=", "len", 55 }, "L14", "L15" } } },
	  { "block",
	    { "label", "L14" },
	    { "bindings" },
	    { "control", { "if", { "=", "v2", 44 }, "L16", "L17" } } },
	  { "block",
	    { "label", "L16" },
	    { "bindings" },
	    { "control", { "return", { "=", { "[]", 54, 1 }, 6 } } } },
	  { "block",
	    { "label", "L17" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } },
	  { "block",
	    { "label", "L15" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } },
	  { "block",
	    { "label", "L11" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } },
	  { "block",
	    { "label", "L9" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } },
	  { "block",
	    { "label", "L5" },
	    { "bindings" },
	    { "control", { "return", { "false" } } } } } }

   local intervals_2 = compute_live_intervals(example_2)
   assert(#intervals_2 == 2)
   assert(intervals_2[1].name == "v1")
   assert(intervals_2[1].start == 2)
   assert(intervals_2[1].finish == 5)
   assert(intervals_2[2].name == "v2")
   assert(intervals_2[2].start == 6)
   assert(intervals_2[2].finish == 9)

   -- "ip[2:2] * 3 = 0"
   example_3 = { "ssa",
                  { "start", "L1" },
                  { "blocks",
                     { "block",
                        { "label", "L1" },
                        { "bindings" },
                        { "control", { "if", { ">=", "len", 34 }, "L4", "L5" } } },
                     { "block",
                        { "label", "L4" },
                        { "bindings" },
                        { "control", { "if", { "=", { "[]", 12, 2 }, 8 }, "L6", "L7" } } },
                     { "block",
                        { "label", "L6" },
                        { "bindings" },
                        { "control", { "return", { "=", { "*64", { "ntohs", { "[]", 16, 2 } }, 3 }, 0 } } } },
                     { "block",
                        { "label", "L7" },
                        { "bindings" },
                        { "control", { "return", { "false" } } } },
                     { "block",
                        { "label", "L5" },
                        { "bindings" },
                        { "control", { "return", { "false" } } } } } }

end
