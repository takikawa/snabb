module(..., package.seeall)

local link = require("core.link")
local packet = require("core.packet")

Test = {}
Test.__index = Test

function Test:new()
   return(setmetatable({}, self))
end

function Test:push()
   if self.output.output then
      while not link.empty(self.input.input) do
         local p = link.receive(self.input.input)
         assert(p ~= false)
         packet.free(p)
      end
   end
end
