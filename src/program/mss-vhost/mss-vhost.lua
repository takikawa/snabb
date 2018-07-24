-- This module implements the `snabb mss-vhost` command

module(..., package.seeall)

local mss   = require("apps.mss_clamp.clamp")
local tap   = require("apps.tap.tap")
local vhost = require("apps.vhost.vhost_user")

function run (args)
  if #args ~= 2 then
    print("usage: mss-vhost <vhost.sock> <tap>")
    main.exit(1)
  end

  local c = config.new()

  config.app(c, "vhost", vhost.VhostUser, {socket_path=args[1], is_server=false})
  config.app(c, "tap", tap.Tap, args[2])
  config.app(c, "clamp", mss.MSSClamp, {mss=1000})

  -- clamp on outgoing SYN packets
  config.link(c, "vhost.tx -> clamp.input")
  --config.link(c, "vhost.tx -> tap.input")
  config.link(c, "clamp.output -> tap.input")

  -- incoming packets just go to VM
  config.link(c, "tap.output -> vhost.rx")

  local done = function ()
    return engine.app_table.vhost.done
  end

  engine.configure(c)
  engine.busywait = false
  engine.main({ done = done })
end
