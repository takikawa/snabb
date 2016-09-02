module(..., package.seeall)

local match = require('pf.match')

Filter = {}

function Filter:new(conf)
   local app = {}
   function app.forward(data, len)
     return len
   end
   function app.drop(data, len)
     -- Could truncate packet here and overwrite with ICMP error if
     -- wanted.
     return nil
   end
   function app.incoming_ip(data, len, ip_base)
     -- Munge the packet.  Return len if we resend the packet.
     return len
   end
   function app.outgoing_ip(data, len, ip_base)
     -- Munge the packet.  Return len if we resend the packet.
     return len
   end
   app.match = match.compile([[match {
     not ip => forward
     -- Drop fragmented packets.
     ip[6:2] & 0x1fff != 0 => drop
     ip src 192.168.0.114 => incoming_ip(&ip[0])
     ip dst 192.168.0.114 => outgoing_ip(&ip[0])
     otherwise => drop
   }]])
   return setmetatable(app, {__index=Filter})
end

function Filter:push ()
   local i, o = self.input.input, self.output.output
   while not link.empty(i) do
      local pkt = link.receive(i)
      local out_len = self:match(pkt.data, pkt.length)
      if out_len then
         pkt.length = out_len
         link.transmit(o, pkt)
      end
   end
end
