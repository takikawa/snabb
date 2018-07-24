-- This module implements the `snabb mss` command

module(..., package.seeall)

local mss   = require("apps.mss_clamp.clamp")
local tap   = require("apps.tap.tap")
local pcap  = require("apps.pcap.pcap")

function run (args)
   if #args ~= 2 then
      print("usage: mss <input-pcap> <tap>")
      main.exit(1)
   end

   local c = config.new()

   config.app(c, "src", pcap.PcapReader, args[1])
   config.app(c, "tap", tap.Tap, args[2])
   config.app(c, "clamp", mss.MSSClamp, {mss=1400})

   config.link(c, "src.output -> clamp.input")
   config.link(c, "clamp.output -> tap.input")

   local done = function ()
      return engine.app_table.src.done
   end

   engine.configure(c)
   engine.busywait = true
   engine.main({ done = done })
end
