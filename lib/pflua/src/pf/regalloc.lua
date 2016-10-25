-- Implements register allocation for pflua's native backend
--
-- Register allocation operates on a post-SSA pflua IR form.
--
-- The result of register allocation is a table mapping variables
-- to register numbers. There are also sub-tables mapping block-local
-- variables to registers for each relevant block label. e.g.,
--
--   { v1 = 1, -- %rcx
--     v2 = 2, -- %rdx
--     v3 = { spill = 0 },
--     num_spilled = 1
--     L4 = { r1 = 0, -- %rax
--            r2 = 8, -- %r8
--          } }
--
-- where a spill table entry means to spill to the stack at the
-- given slot. The num_spilled entry indicates the max number
-- of spilled variables and hence stack slots needed.
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
--
-- We conduct a simple allocation in which variables
-- have a single live range with no holes, which should work well
-- since the IR is so constrained.

module(...,package.seeall)

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

-- Given an SSA IR, compute the linear scan live intervals
-- This is very easy with our loop-less SSA representation since
-- the live interval simply starts at first occurrence of a
-- "bindings" for a variable and ends at the last reference.
--
-- A live interval is a table
--   { name = String, start = String, finish = String }
--
-- The start and finish fields are block labels, and they are
-- traversed according to the IR order (depth-first).
--
local function compute_live_intervals(ssa)
   local live_intervals = {}

   for _, label in ipairs(ssa.order) do
      local block = ssa.blocks[label]
      local bindings = block.bindings

      for _, binding in pairs(bindings) do
	 local interval = { name = binding.name,
			    start = label,
			    finish = nil }
	 table.insert(live_intervals, interval)
      end

      find_live_in_control(label, block.control, live_intervals)
   end

   return live_intervals
end

-- Do instruction selection on arithmetic and boolean
-- expressions in order to convert them into straight-line code
--
-- Only call this on blocks with a { "return", { rel_op ... } }
-- control AST.
--
-- Returns a new list of bindings to merge and a new control AST
-- with lower-level arithmetic pseudo-instructions
--
-- New bindings are given names prefixed with "r" as in "r1"
-- since they are pseudo-registers. These bindings are local to
-- the block and thus don't follow the SSA structure
-- (i.e., they are not unique across blocks).
function simplify_exprs(block)
   local rel_expr = block.control[2]
   local bindings = block.bindings

   local reg_num = 1
   local function new_register()
      local new_var = string.format("r%d", reg_num)
      reg_num = reg_num + 1
      return new_var
   end

   local function simplify(expr, bindings)
      if type(expr) == "string" then
         return expr
      elseif type(expr) == "number" or expr[1] == "[]" then
         local reg = new_register()
         table.insert(bindings, { name = reg, value = expr })
         return reg

      -- three register addition
      elseif (expr[1] == "+" and type(expr[2]) == "table" and
              expr[2][1] == "+") then
         local expr1 = simplify(expr[2][2], bindings)
         local expr2 = simplify(expr[2][3], bindings)
         local expr3 = simplify(expr[3], bindings)
         return { "+3", expr1, expr2, expr3 }
      elseif (expr[1] == "+" and type(expr[3]) == "table" and
              expr[3][1] == "+") then
         local expr1 = simplify(expr[3][2], bindings)
         local expr2 = simplify(expr[3][3], bindings)
         local expr3 = simplify(expr[2], bindings)
         return { "+3", expr1, expr2, expr3 }

      -- addition with immediate
      elseif expr[1] == "+" and type(expr[2]) == "number" then
         local expr3 = simplify(expr[3], bindings)
         return { "+const", expr3, expr[2] }
      elseif expr[1] == "+" and type(expr[3]) == "number" then
         local expr2 = simplify(expr[2], bindings)
         return { "+const", expr2, expr[3] }

      -- multiplication with constant
      elseif expr[1] == "*" and type(expr[2]) == "number" then
         local expr3 = simplify(expr[3], bindings)
         return { "*const", expr3, expr[2] }
      elseif expr[1] == "*" and type(expr[3]) == "number" then
         local expr2 = simplify(expr[2], bindings)
         return { "*const", expr2, expr[3] }

      -- generic multiplication
      elseif expr[1] == "*" then
         local expr2 = simplify(expr[2], bindings)
         local expr3 = simplify(expr[3], bindings)
         return { "*", expr2, expr3 }

      -- generic addition
      elseif expr[1] == "*" then
         local expr2 = simplify(expr[2], bindings)
         local expr3 = simplify(expr[3], bindings)
         return { "+", expr2, expr3 }
      end
   end

   local lhs = rel_expr[2]
   local rhs = rel_expr[3]

   local new_lhs = simplify(lhs, bindings)
   local reg = new_register()
   table.insert(bindings, { name = reg, value = new_lhs })
   new_lhs = reg

   if type(rhs) == "number" then
      new_rhs = rhs
   else
      new_rhs = simplify(rhs, bindings)
      reg = new_register()
      table.insert(bindings, { name = reg, value = new_rhs })
      new_rhs = reg
   end

   block.control = { "return", { rel_expr[1], new_lhs, new_rhs } }
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
   local utils = require("pf.utils")

   -- tests of simplification/instruction selection pass on arithmetic
   -- and boolean expressions
   local function test(block, expected)
      simplify_exprs(block)
      utils.assert_equals(block.control, expected.control)
      utils.assert_equals(block.bindings, expected.bindings)
   end

   test({ label = "L2",
          bindings = {},
          control = { "return",
                       { "=", { "+", { "[]", 12, 2 }, 5 }, 1 } } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "+const", "r1", 5 } } },
          control = { "return", { "=", "r2", 1 } } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                       { "=", { "*", { "[]", 12, 2 }, 5 }, 1 } } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "*const", "r1", 5 } } },
          control = { "return", { "=", "r2", 1 } } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                       { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 } } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "[]", 14, 2 } },
                       { name = "r3", value = { "*", "r1", "r2" } } },
          control = { "return", { "=", "r3", 1 } } })

   -- "ip"
   local example_1 =
      { start = "L1",
	order = { "L1", "L4", "L5" },
	blocks =
	   { L1 = { label = "L1",
		    bindings = {},
		    control = { "if", { ">=", "len", 14 }, "L4", "L5" } },
	     L4 = { label = "L4",
		    bindings = {},
		    control = { "return", { "=", { "[]", 12, 2 }, 8 } } },
	     L5 = { label = "L5",
		    bindings = {},
		    control = { "return", { "false " } } } } }

   assert(#compute_live_intervals(example_1) == 0)

   local example_2 =
      { start = "L1",
	order = { "L1", "L4", "L6", "L7", "L8", "L10", "L12", "L13",
		  "L14", "L16", "L17", "L15", "L11", "L9", "L5" },
	blocks =
	   { L1 = { label = "L1",
	            bindings = {},
	            control = { "if", { ">=", "len", 34 }, "L4", "L5" } },
	     L4 = { label = "L4",
	            bindings = { { name = "v1", value = { "[]", 12, 2 } } },
	            control = { "if", { "=", "v1", 8 }, "L6", "L7" } },
	     L6 = { label = "L6",
	            bindings = {},
	            control = { "return", { "=", { "[]", 23, 1 }, 6 } } },
	     L7 = { label = "L7",
	            bindings = {},
	            control = { "if", { ">=", "len", 54 }, "L8", "L9" } },
	     L8 = { label = "L8",
	            bindings = {},
	            control = { "if", { "=", "v1", 56710 }, "L10", "L11" } },
	     L10 = { label = "L10",
	             bindings = { { name = "v2", value = { "[]", 20, 1 } } },
	             control = { "if", { "=", "v2", 6 }, "L12", "L13" } },
	     L12 = { label = "L12",
	             bindings = {},
	             control = { "return", { "true" } } },
	     L13 = { label = "L13",
	             bindings = {},
	             control = { "if", { ">=", "len", 55 }, "L14", "L15" } },
	     L14 = { label = "L14",
	             bindings = {},
	             control = { "if", { "=", "v2", 44 }, "L16", "L17" } },
	     L16 = { label = "L16",
	             bindings = {},
	             control = { "return", { "=", { "[]", 54, 1 }, 6 } } },
	     L17 = { label = "L17",
	             bindings = {},
	             control = { "return", { "false" } } },
	     L15 = { label = "L15",
	             bindings = {},
	             control = { "return", { "false" } } },
	     L11 = { label = "L11",
	             bindings = {},
	             control = { "return", { "false" } } },
	     L9 = { label = "L9",
	            bindings = {},
	            control = { "return", { "false" } } },
	     L5 = { label = "L5",
	            bindings = {},
	            control = { "return", { "false" } } } } }

   local intervals_2 = compute_live_intervals(example_2)
   assert(#intervals_2 == 2)
   assert(intervals_2[1].name == "v1")
   assert(intervals_2[1].start == "L4")
   assert(intervals_2[1].finish == "L8")
   assert(intervals_2[2].name == "v2")
   assert(intervals_2[2].start == "L10")
   assert(intervals_2[2].finish == "L14")

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
