module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local filter = require("program.example_pfmatch.filter")

function run(parameters)
  if not (#parameters == 2) then
    print("Usage: example_pfmatch <input> <output>")
    main.exit(1)
  end

  local input = parameters[1]
  local output = parameters[2]

  local c = config.new()

  config.app(c, "capture", pcap.PcapReader, input)
  config.app(c, "filter", filter.Filter)
  config.app(c, "output_file", pcap.PcapWriter, output)

  config.link(c, "capture.output -> filter.input")
  config.link(c, "filter.output -> output_file.input")

  engine.configure(c)
  engine.main({duration = 1, report = {showlinks = true}})
end
