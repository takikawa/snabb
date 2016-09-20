module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local scan = require("apps.scan_suppression.scan_suppression")

function run(parameters)
  if not (#parameters == 3) then
    print("Usage: example_scan <network> <input> <output>")
    main.exit(1)
  end

  local network = parameters[1]
  local input = parameters[2]
  local output = parameters[3]

  local c = config.new()

  config.app(c, "capture", pcap.PcapReader, input)
  config.app(c, "scan", scan.Scanner, { scan_inside_network = network })
  config.app(c, "output_file", pcap.PcapWriter, output)

  config.link(c, "capture.output -> scan.input")
  config.link(c, "scan.output -> output_file.input")

  engine.configure(c)
  engine.main({duration = 10, report = {showlinks = true}})
end
