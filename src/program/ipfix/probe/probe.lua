-- This module implements the `snabb flow_export` command

module(..., package.seeall)

local lib      = require("core.lib")
local pci      = require("lib.hardware.pci")
local cache    = require("apps.ipfix.cache")
local conf     = require("apps.ipfix.config")
local meter    = require("apps.ipfix.meter")
local exporter = require("apps.ipfix.export")

local long_opts = {
   help = "h",
   duration = "D",
   config = "f",
   ["netflow-v9"] = 0,
   ["ipfix"] = 0,
}

function run (args)
   local duration
   local ipfix_version = 10
   local config_file

   -- TODO: better input validation
   local opt = {
      h = function (arg)
         print(require("program.ipfix.probe.README_inc"))
         main.exit(0)
      end,
      D = function (arg)
         duration = assert(tonumber(arg), "expected number for duration")
      end,
      f = function (arg)
         config_file = arg
      end,
      ipfix = function (arg)
         ipfix_version = 10
      end,
      ["netflow-v9"] = function (arg)
         ipfix_version = 9
      end
   }

   args = lib.dogetopt(args, opt, "hD:f:", long_opts)
   if #args ~= 0 then
      print(require("program.ipfix.probe.README_inc"))
      main.exit(1)
   end

   local yang_config = conf.load_ipfix_config(config_file)

   local obvs_points = assert(yang_config.ipfix.observation_point,
                              "missing observation points")

   if obvs_points.occupancy == 0 then
      error("Expected at least one observation point configured")
   end

   local c = config.new()

   local interfaces = {}
   pci.scan_devices()
   for config in obvs_points:iterate() do
      local app_name = string.format("meter-%s", config.name)
      local src_name = string.format("source-%s", config.name)
      local intf = assert(config.ifName, "ifName required")
      local source

      -- if it's an interface name for a PCI device, then load up the driver
      local device_info = pci.devices[intf]
      if device_info and not interfaces[intf] then
         source = { require(device_info.driver).driver, intf }
      else
         source = interfaces[intf]
      end

      -- otherwise assume it's a RawSocket name
      source = { require("apps.socket.raw").RawSocket, intf }

      config.app(c, app_name, meter.FlowMeter, config)
      config.app(c, src_name, unpack(source))
      config.link(c, src_name .. ".tx -> " .. app_name .. ".input")
   end

   local cache_configs = assert(yang_config.cache, "missing caches")
   if cache_configs.occupancy == 0 then
      error("Expected at least one cache configured")
   end

   for conf in cache_configs:iterate() do
      cache.register_new_cache(conf)
   end

   local exporter_configs = assert(yang_config.exportingProcess)
   for config in exporter_configs:iterate() do
      local app_name  = string.format("exporter-%s", config.name)
      local sink_name = string.format("sink-%s", config.name)
      config.app(c, app_name, exporter.FlowExporter, config)

      -- TODO: this code is similar to above, abstract it
      local intf = assert(config.ifName, "ifName required")
      local sink

      local device_info = pci.devices[intf]
      if device_info and not interfaces[intf] then
         sink = { require(device_info.driver).driver, intf }
      else
         sink = interfaces[intf]
      end

      -- otherwise assume it's a RawSocket name
      sink = { require("apps.socket.raw").RawSocket, intf }
      config.app(c, sink_name, unpack(sink))
      config.link(c, app_name .. ".output -> " .. sink_name .. ".rx")
   end

   local done
   if not duration then
      done = function ()
         return engine.app_table.source.done
      end
   end

   engine.configure(c)
   engine.busywait = true
   engine.main({ duration = duration, done = done })
end
