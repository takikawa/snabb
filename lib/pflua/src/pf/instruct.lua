-- This module implements an "instruction selection" pass over the
-- arithmetic expressions inside conditionals and return statements.
--
-- This process greedily goes over the arithmetic expression tree,
-- creating operations that are machine instructions.
--
-- This generates the following new operations:
--   *const
--   +const
--   *3
--
-- Intermediate expressions are also lifted into bindings so that
-- local register allocation can be done.

module(...,package.seeall)

-- Only call this on blocks with one of the following forms:
--   * { "return", { rel_op ... } }
--   * { "if", { rel_op ...}, ... }
--
-- Merges new bindings for intermediate expressions into the block's
-- bindings and assigns a new control AST
--
-- New bindings are given names prefixed with "r" as in "r1"
-- since they are pseudo-registers. These bindings are local to
-- the block and thus don't follow the SSA structure
-- (i.e., they are not unique across blocks).
function lower_exprs(block)
   local control  = block.control
   local rel_expr = control[2]
   local bindings = block.bindings

   local reg_num = 1
   local function new_register()
      local new_var = string.format("r%d", reg_num)
      reg_num = reg_num + 1
      return new_var
   end

   local function simplify(expr, bindings)
      local utils = require("pf.utils")
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
      elseif expr[1] == "+" then
         local expr2 = simplify(expr[2], bindings)
         local expr3 = simplify(expr[3], bindings)
         return { "+", expr2, expr3 }
      end
   end

   local lhs = rel_expr[2]
   local rhs = rel_expr[3]
   local new_lhs, new_rhs

   if type(lhs) == "string" then
      new_lhs = lhs
   else
     new_lhs = simplify(lhs, bindings)
     if type(new_lhs) == "table" then
        reg = new_register()
        table.insert(bindings, { name = reg, value = new_lhs })
        new_lhs = reg
     end
   end

   if type(rhs) == "number" then
      new_rhs = rhs
   else
      new_rhs = simplify(rhs, bindings)
      if type(new_rhs) == "table" then
         reg = new_register()
         table.insert(bindings, { name = reg, value = new_rhs })
         new_rhs = reg
      end
   end

   if control[1] == "return" then
      block.control = { "return", { rel_expr[1], new_lhs, new_rhs } }
   else -- "if"
      block.control =
         { "if",
           { rel_expr[1], new_lhs, new_rhs },
           control[3],
           control[4] }
   end
end

function lower(ssa)
   local blocks = ssa.blocks

   for _, label in pairs(ssa.order) do
      local block   = blocks[label]
      local control = block.control

      if ((control[1] == "return" and #control[2] > 1)
          or control[1] == "if") then
         lower_exprs(block)
      end
   end
end

function selftest()
   local utils = require("pf.utils")

   -- tests of simplification/instruction selection pass on arithmetic
   -- and boolean expressions
   local function test(block, expected)
      lower_exprs(block)
      utils.assert_equals(block.control, expected.control)
      assert(#block.bindings == #expected.bindings)
   end

   test({ label = "L1",
          bindings = {},
          control = { "if", { ">=", "len", 14 }, "L4", "L5" } },
        { label = "L1",
          bindings = {},
          control = { "if", { ">=", "len", 14 }, "L4", "L5" } })
   test({ label = "L4",
          bindings = {},
          control = { "return", { "=", { "[]", 12, 2 }, 1544 } } },
        { label = "L4",
          bindings = { { name = "r1", value = { "[]", 12, 2 } } },
          control = { "return", { "=", "r1", 1544 } } })

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
          control = { "return", { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 } } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "[]", 14, 2 } },
                       { name = "r3", value = { "*", "r1", "r2" } } },
          control = { "return", { "=", "r3", 1 } } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "+", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "+const", "r1", 5 } } },
          control = { "if", { "=", "r2", 1 }, "L4", "L5" } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "*const", "r1", 5 } } },
          control = { "if", { "=", "r2", 1 }, "L4", "L5" } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 },
                      "L4", "L5" } },
        { label = "L2",
          bindings = { { name = "r1", value = { "[]", 12, 2 } },
                       { name = "r2", value = { "[]", 14, 2 } },
                       { name = "r3", value = { "*", "r1", "r2" } } },
          control = { "if", { "=", "r3", 1 }, "L4", "L5" } })
end
