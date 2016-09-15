module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local scan = require("apps.scan_suppression.scan_suppression")

function run(parameters)
  if not (#parameters == 2) then
    print("Usage: example_scan <input> <output>")
    main.exit(1)
  end

  local input = parameters[1]
  local output = parameters[2]

  local c = config.new()

  config.app(c, "capture", pcap.PcapReader, input)
  config.app(c, "scan", scan.Scanner)
  config.app(c, "output_file", pcap.PcapWriter, output)

  config.link(c, "capture.output -> scan.input")
  config.link(c, "scan.output -> output_file.input")

  engine.configure(c)
  engine.main({duration = 1, report = {showlinks = true}})
end
