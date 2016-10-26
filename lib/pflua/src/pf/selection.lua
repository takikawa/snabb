-- This module implements an "instruction selection" pass over the
-- SSA IR and produces pseudo-instructions for register allocation
-- and code generation.
--
-- This uses a greed matching algorithm over the tree.
--
-- This generates an array of pseudo-instructions like this:
--
--   { { "mov", "r1", "r2" } }
--     { "+", "r1", "r3" } }
--
-- The instructions available are:
--   * ret-true
--   * ret-false
--   * load
--   * mov
--   * add
--   * add-3
--   * add-i
--   * mul
--   * mul-i
--   * cjmp

module(...,package.seeall)

local negate_op = { ["="] = "!=", ["!="] = "=",
                    [">"] = "<=", ["<"] = ">=",
                    [">="] = "<", ["<="] = ">" }

-- extract a number from an SSA IR label
function label_num(label)
   return tonumber(string.match(label, "L(%d+)"))
end

-- Convert a block to a sequence of pseudo-instructions
--
-- Virtual registers are given names prefixed with "r" as in "r1".
-- SSA variables remain prefixed with "v"
local function select_block(block, new_register, instructions)
   local control  = block.control
   local bindings = block.bindings

   local function emit(instr)
      table.insert(instructions, instr)
   end

   -- do instruction selection on an arithmetic expression
   -- returns the destination register or immediate
   local function select_arith(expr)
      if type(expr) == "number" or type(expr) == "string" then
         return expr

      elseif expr[1] == "[]" then
         reg = new_register()
         emit({ "load", reg, expr[2], expr[3] })
         return reg

      -- three register addition
      elseif (expr[1] == "+" and type(expr[2]) == "table" and
              expr[2][1] == "+") then
         local reg1 = select_arith(expr[2][2])
         local reg2 = select_arith(expr[2][3])
         local reg3 = select_arith(expr[3])
         emit({ "add-3", reg1, reg2, reg3 })
         return reg1
      elseif (expr[1] == "+" and type(expr[3]) == "table" and
              expr[3][1] == "+") then
         local reg1 = select_arith(expr[3][2])
         local reg2 = select_arith(expr[3][3])
         local reg3 = select_arith(expr[2])
         emit({ "add-3", reg1, reg2, reg3 })
         return reg1

      -- addition with immediate
      elseif expr[1] == "+" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         emit({ "add-i", reg3, expr[2] })
         return reg3
      elseif expr[1] == "+" and type(expr[3]) == "number" then
         local reg2 = select_arith(expr[2])
         emit({ "add-i", reg2, expr[3] })
         return reg2

      -- multiplication with constant
      elseif expr[1] == "*" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         emit({ "mul-i", reg3, expr[2] })
         return reg3
      elseif expr[1] == "*" and type(expr[3]) == "number" then
         local reg2 = select_arith(expr[2])
         emit({ "mul-i", reg2, expr[3] })
         return reg2

      -- generic multiplication
      elseif expr[1] == "*" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         -- TODO: consider inserting movs here to make RA easier?
         emit({ "mul", reg2, reg3 })
         return reg2

      -- generic addition
      elseif expr[1] == "+" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         -- TODO: consider inserting movs here to make RA easier?
         emit({ "add", reg2, reg3 })
         return reg2
      end
   end

   local function select_bool(expr)
      reg1 = select_arith(expr[2])
      reg2 = select_arith(expr[3])
      emit({ "cmp", reg1, reg2 })
   end

   emit({ "label", label_num(block.label) })

   -- assumes that a binding RHS always has a load in it
   for _, binding in ipairs(bindings) do
      local rhs = binding.value
      emit({ "load", binding.name, rhs[2], rhs[3] })
   end

   if control[1] == "return" then
      local result = control[2]

      if result[1] == "false" then
         emit({ "ret-false" })
      elseif result[1] == "true" then
         emit({ "ret-true" })
      else
         select_bool(result)
         emit({ "cjmp", result[1], "true-label" })
         emit({ "ret-false" })
      end

   elseif control[1] == "if" then
      local cond = control[2]
      select_bool(cond)
      emit({ "cjmp", negate_op[cond[1]], control[4] })
   end
end

local function make_new_register(reg_num)
   return
      function()
         local new_var = string.format("r%d", reg_num)
         reg_num = reg_num + 1
         return new_var
      end
end

function select(ssa)
   local blocks = ssa.blocks
   local instructions = {}

   local reg_num = 1
   local new_register = make_new_register(reg_num)

   for _, label in pairs(ssa.order) do
      local block   = blocks[label]

      select_block(block, new_register, instructions)
   end
end

function selftest()
   local utils = require("pf.utils")

   -- tests of simplification/instruction selection pass on arithmetic
   -- and boolean expressions
   local function test(block, expected)
      local instructions = {}
      local counter = 1
      local new_register = make_new_register(counter)
      select_block(block, new_register, instructions)
      utils.assert_equals(instructions, expected)
   end

   test({ label = "L1",
          bindings = {},
          control = { "if", { ">=", "len", 14 }, "L4", "L5" } },
       {  { "label", 1 },
          { "cmp", "len", 14 },
          { "cjmp", "<", "L5" } })

   test({ label = "L4",
          bindings = {},
          control = { "return", { "=", { "[]", 12, 2 }, 1544 } } },
        { { "label", 4 },
          { "load", "r1", 12, 2 },
          { "cmp", "r1", 1544 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                      { "=", { "+", { "[]", 12, 2 }, 5 }, 1 } } },
       {  { "label", 2 },
          { "load", "r1", 12, 2 },
          { "add-i", "r1", 5 },
          { "cmp", "r1", 1 },
          { "cjmp", "=", "true-label"},
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                      { "=", { "*", { "[]", 12, 2 }, 5 }, 1 } } },
        { { "label", 2 },
          { "load", "r1", 12, 2 },
          { "mul-i", "r1", 5 },
          { "cmp", "r1", 1 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return", { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 } } },
        { { "label", 2 },
          { "load", "r1", 12, 2 },
          { "load", "r2", 14, 2 },
          { "mul", "r1", "r2" },
          { "cmp", "r1", 1 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "+", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { { "label", 2 },
          { "load", "r1", 12, 2 },
          { "add-i", "r1", 5 },
          { "cmp", "r1", 1 },
          { "cjmp", "!=", "L5" } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { { "label", 2 },
          { "load", "r1", 12, 2 },
          { "mul-i", "r1", 5 },
          { "cmp", "r1", 1 },
          { "cjmp", "!=", "L5" } } )

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 },
                      "L4", "L5" } },
        { { "label", 2 },
          { "load", "r1", 12, 2 },
          { "load", "r2", 14, 2 },
          { "mul", "r1", "r2" },
          { "cmp", "r1", 1 },
          { "cjmp", "!=", "L5" } })

   test({ label = "L10",
          bindings = { { name = "v2", value = { "[]", 20, 1 } } },
          control = { "if", { "=", "v2", 6 }, "L12", "L13" } },
        { { "label", 10 },
          { "load", "v2", 20, 1 },
          { "cmp", "v2", 6 },
          { "cjmp", "!=", "L13" } })
end
