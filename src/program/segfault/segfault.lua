module(..., package.seeall)

-- Demonstration of a segfault due to a "bad" configuration

local pcap = require("apps.pcap.pcap")
local intel_mp = require("apps.intel_mp.intel_mp")
local basic_apps = require("apps.basic.basic_apps")

function run (parameters)
   if not (#parameters == 2) then
      print("Usage: example <interface> <interface>")
      main.exit(1)
   end
   local interface1 = parameters[1]
   local interface2 = parameters[2]

   -- First configure an app network totally normally, note that it has a
   -- "playback" app using txq = 0
   local c = config.new()
   config.app(c, "sink", basic_apps.Sink)
   config.app(c, "capture", basic_apps.Source)

   config.app(c, "playback", intel_mp.driver, { pciaddr = interface1, txq = 0 })
   config.app(c, "receive", intel_mp.driver, { pciaddr = interface2, rxq = 0 })

   config.link(c, "capture.output -> playback.input")
   config.link(c, "receive.output -> sink.input")

   engine.configure(c)
   engine.main({duration=1, report = {showlinks=true}})

   -- Now make a new configuration
   --
   -- Snabb does not shut down apps that have identical configurations/name, so the
   -- "playback" app remains from the last run (with its tx descriptor registers
   -- pointing to the same place).
   --
   -- But the "playback1" app also configures txq = 0 and initializes the tx queue,
   -- and that sets self.tdh (the cache of the TDH register) to zero. But this clashes
   -- with the TDH from the still-running original app, causing a segfault (because
   -- the app thinks packets are ready to be freed, but they aren't).
   local c2 = config.new()
   config.app(c2, "sink", basic_apps.Sink)
   config.app(c2, "tee", basic_apps.Tee)
   config.app(c, "capture", basic_apps.Source)

   config.app(c2, "playback", intel_mp.driver, { pciaddr = interface1, txq = 0 })
   config.app(c2, "playback1", intel_mp.driver, { pciaddr = interface1, txq = 0, mtu = 9015 })
   config.app(c2, "receive", intel_mp.driver, { pciaddr = interface2, rxq = 0 })

   config.link(c, "capture.output -> playback.input")
   config.link(c2, "tee.output2 -> playback1.input")
   config.link(c2, "receive.output -> sink.input")

   engine.configure(c2)
   engine.main({duration=1, report = {showlinks=true}})
end
