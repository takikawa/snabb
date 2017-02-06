module(..., package.seeall)

local pcap   = require("apps.pcap.pcap")

function run (args)
   local c = config.new()

   config.app(c, "source", require("apps.pcap.pcap").PcapReader, "/tmp/input.pcap")
   config.app(c, "test", require("apps.test.test").Test)
   config.app(c, "sink", pcap.PcapWriter, "/tmp/output.pcap")

   config.link(c, "source.output -> test.input")
   config.link(c, "test.output -> sink.input")

   engine.configure(c)
   engine.main({duration = 0.5})
   print("OK")
end
