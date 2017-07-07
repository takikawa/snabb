# Change Log

## [3.1.8] - 2017-03-10

* Retry ARP and NDP resolution indefinitely.

## [3.1.7] - 2017-01-20

* Reverts commit 86b9835 ("Remove end-addr in psid-map"), which 
  introduced a severe regression that caused high packet loss due
  to not maching softwires.

## [3.1.6] - 2017-01-19

* Add basic error reporting to snabb-softwire-v1.

* Add property-based testing for snabb config.

* Add socket support for "snabb config listen".

* Clean stale object files in program/lwaftr and program/snabbvmx.

* Fix "lwaftr query". Added selftest.

* Fix "snabb config remove" on arrays.

* Fix bug parsing empty strings in YANG parser.

* Fix tunnel-path-mtu and tunnel-payload-mtu in ietf-softwire.

* Respond to ping packets to internal and external interfaces when
  running in on-a-stick mode. Added test.

* Several improvements in lwaftrctl script (no screen command, connect
  via telnet, internet access in VM).

## [3.1.5] - 2016-12-09

 * Improve "snabb ps" output.  Processes with a "*" by them are
   listening for "snabb config" connections.

 * Fix race condition in multiprocess --reconfigurable mode.

 * Improve configuration change throughput.

 * Add "snabb config bench" utility for benchmarking configuration
   throughput.

 * Add automated "snabb config" tests.

 * Improve error message when --cpu setting was not possible.

## [3.1.4] - 2016-12-09

 * Fix memory corruption bug in main process of --reconfigurable "snabb
   lwaftr run" that would cause the dataplane to prematurely exit.

## [3.1.3] - 2016-12-08

 * Fix performance problem for --reconfigurable "snabb lwaftr run"
   wherein the main coordination process would also get scheduled on the
   data plane CPU.  Also re-enable ingress drop monitor and --real-time
   support for multiprocess lwaftr.

 * "snabb config --help" fixes.

 * Allow "snabb lwaftr query", "snabb lwaftr monitor", "snabbvmx query",
   and "snabbvmx top" to locate Snabb instances by name.

## [3.1.2] - 2016-12-07

 * Re-enabled multi-process mode for --reconfigurable "snabb lwaftr
   run", including support for "snabb config get-state".

 * Improve memory consumption when parsing big configurations, such as a
   binding table with a million entries.

 * Re-enable CSV-format statistics for "snabb lwaftr bench" and "snabb
   lwaftr run", which were disabled while we landed multiprocess
   support.

 * Fix "snabb ps --help".

## [3.1.1] - 2016-12-06

A hotfix to work around bugs in multiprocess support when using Intel
NICs.

 * Passing --reconfigurable to "snabb lwaftr run" now just uses a single
   process while we sort out multiprocess issues.

 * Fixed "snabb lwaftr query" and "snabb top", broken during
   refactoring.

## [3.1.0] - 2016-12-06

Adding "ietf-softwire" support, process separation between control and
the data plane, and some configuration file changes.

 * Passing --reconfigurable to "snabb lwaftr run" now forks off a
   dedicated data plane child process.  This removes the overhead of
   --reconfigurable that was present in previous releases.

 * Add support for ietf-softwire.  Pass the "-s ietf-softwire" to "snabb
   config" invocations to use this schema.

 * Add support for fast binding-table updates.  This is the first
   version since the YANG migration that can make fast updates to
   individual binding-table entries without causing the whole table to
   reload, via "snabb config add
   /softwire-config/binding-table/softwire".  See "snabb config"
   documentation for more on how to use "snabb config add" and "snabb
   config remove".

 * Add support for named lwAFTR instances.  Pass "--name foo" to the
   "snabb lwaftr run" command to have it claim a name on a machine.
   "snabb config" can identify the remote Snabb instance by name, which
   is often much more convenient than using the instance's PID.

 * Final tweaks to the YANG schema before deployment -- now the
   binding-table section is inside softwire-config, and the
   configuration file format is now enclosed in "softwire-config {...}".
   It used to be that only YANG "container" nodes which had "presence
   true;" would have corresponding data nodes; this was a mistake.  The
   new mapping where every container node from the YANG schema appears
   in the data more closely follows the YANG standard XML mapping that
   the XPath expressions are designed to operate over.

   Additionally, the "br" leaf inside "snabb-softwire-v1" lists is now a
   1-based index into the "br-address" leaf-list instead of a zero-based
   index.

   The "snabb lwaftr migrate-configation --from=3.0.1" command can
   migrate your 3.0.1 configuration files to the new format.  See "snabb
   lwaftr migrate-configuration --help" for more details.  The default
   "--from" version is "legacy", meaning pre-3.0 lwAFTR configurations.

## [3.0.1] - 2016-11-28

A release to finish "snabb config" features.

 * New "snabb config" commands "get-state", "add", "remove", and
   "listen".  See [the `snabb config` documentation](../../config/README.md)
   for full details.

 * The "get-state", "get", "set", "add", and "remove" "snabb config"
   commands can now take paths to indicate sub-configurations on which
   to operate.  This was documented before but not yet implemented.

## [3.0.0] - 2016-11-18

A change to migrate the lwAFTR to use a new YANG-based configuration.

 * New configuration format based on YANG.  To migrate old
   configurations, run "snabb lwaftr migrate-configation old.conf" on
   the old configuration.  See the [snabb-softwire-v1.yang
   schema](../../../lib/yang/snabb-softwire-v1.yang) or
   [configuration.md](./configuration.md) for full details
   on the new configuration format.

 * Send ICMPv6 unreachable messages from the most appropriate source address
   available (the one associated with a B4 if possible, or else the one the
   packet one is in reply to had as a destination.)

 * Add support for ARP resolution of the next hop on the external (IPv4)
   interface.

 * Add support for virtualized control planes via Snabb vMX.  See [the
   `snabbvmx` documentation](../../snabbvmx/doc/README.md) for more.

 * Add many more counters, used to diagnose the path that packets take
   in the lwAFTR.  See [counters.md](./counters.md) for
   more.

 * Add "snabb config" set of commands, to replace "snabb lwaftr control".
   See [the `snabb config` documentation](../../config/README.md) for
   full details.

 * Add initial support for being able to reconfigure an entire lwAFTR
   process while it is running, including changes that can add or remove
   ingresss or egress filters, change NIC settings, or the like.  Pass
   the `--reconfigurable` argument to `snabb lwaftr run`, then interact
   with the lwAFTR instance via `snabb config`.  Enabling this option
   currently has a small performance impact; this will go away in the
   next release.  A future release will also support efficient
   incremental binding-table updates.

 * Many updates from upstream Snabb.

## [2.10] - 2016-06-17

A Snabb NFV performance fix, which results in more reliable performance
when running any virtualized workload, including the lwAFTR.

 * Fix a situation in the NFV which caused runtime behavior that the JIT
   compiler did not handle well.  This fixes the situation where
   sometimes Snabb NFV would wedge itself into a very low-throughput
   state.

 * Disable jit.flush() mechanism in Snabb NFV, to remove a source of
   divergence with upstream Snabb NFV.  Ingress drops in the NFV are
   still detected and printed to the console, but as warnings.

 * Remove remaining sources of backpressure in the lwAFTR.

## [2.9] - 2016-06-09

A performance release, speeding up both the core lwaftr operations as
well as the support for running Snabb on virtualized interfaces.

 * Change Snabb representation of packets to have "headroom".
   Prepending a header to a packet, as when encapsulating a packet in a
   lightweight 4-over-6 softwire, can use this headroom instead of
   shifting the packet's payload around in memory.  Taking off a header,
   as in decapsulation, can likewise just adjust the amount of headroom.
   Likewise when sending packets to a host Snabb NFV the virtio system
   can place these headers in the headroom as well, instead of needing
   multiple virtio scatter-gather buffers.

 * Fix a bug in Snabb NFV by which it would mistakenly cache the Virtio
   features that it used when negotiating with QEMU at startup for the
   Snabb process.

 * Remove backpressure on the intel driver.  This means that if Snabb
   NFV is dropping packets at ingress, it is because Snabb NFV is too
   slow.  If it is dropping them on the NIC -> Virtio link, it is
   because the guest is too slow.

Note: this version of the lwaftr *needs* a fixed version of Snabb NFV to
run virtualized.  The patches are headed upstream, but for now, use the
Snabb NFV from this release instead of the ones from upstream.

## [2.8] - 2016-06-03

A bug-fix and documentation release.

 * Fix ability to load in ingress and egress filters from a file.  This
   feature was originally developed on our main branch and backported in
   v2.5, but the backport was missing a necessary fix from the main
   branch.

 * Update documentation on ingress and egress filtering, giving several
   examples.

 * Added performance analysis of the overhead of ingress and egress
   filtering.  See
   https://github.com/Igalia/snabb/blob/lwaftr_starfruit/src/program/lwaftr/doc/filters-performance.md.

 * Updated documentation for performance tuning.  See
   https://github.com/Igalia/snabb/blob/lwaftr_starfruit/src/program/lwaftr/doc/performance.md

 * Add a time-stamp for the JIT self-healing behavior, and adapt the
   message to be more helpful.

 * The "loadtest" command now separates reporting of drops that were
   because the load generator was not able to service its receive queue
   in time, and drops which originate in the remote tested process.

## [2.7] - 2016-05-19

A performance, feature, and bug-fix release.

 * Fix a situation where the JIT self-healing behavior introduced in
   v2.4 was not being triggered when VLANs were enabled.  Detecting when
   to re-train the JIT depends on information from the network card, and
   the Snabb Intel 82599 driver has two very different code paths
   depending on whether VLAN tagging is enabled or not.  Our fix that we
   introduced in v2.4 was only working if VLAN tagging was not enabled.
   The end result was that performance was not as reliably good as it
   should be.

 * Add the ability for the "loadtest" command to produce different load
   transient shapes.  See "snabb lwaftr loadtest --help" for more
   details.

## [2.6] - 2016-05-18

A bug fix release.

 * Fix ability to dump the running binding table to a text file.  Our
   previous fix in 2.5 assumed that we could find the original binding
   table on disk, but that is not always the case, for example if the
   binding table was changed or moved.

   On the bright side, the binding table dumping facility will now work
   even if the binding table is changed at run-time, which will be
   necessary once we start supporting incremental binding-table updates.

## [2.5] - 2016-05-13

A bug fix release.

 * Fix bug in the NDP implementation.  Before, the lwAFTR would respond
   to neighbor solicitations to any of the IPv6 addresses associated
   with tunnel endpoints, but not to the IPv6 address of the interface.
   This was exactly backwards and has been fixed.

 * Fix ability to dump the running binding table to a text file.  This
   had been fixed on the main development branch before v2.4 but we
   missed it when selecting the features to back-port to the 2.x release
   branch.

 * Add ability to read in ingress and egress filters from files.  If the
   filter value starts with a "<", it is interpreted as a file that
   should be read.  For example, `ipv6_egress_filter =
   <ipv6-egress-filter.txt"`.  See configuration.md.

## [2.4] - 2016-05-03

A bug fix, performance tuning, and documentation release.

 * Fix limitations and bugs in the NDP implementation.  Before, if no
   reply to the initial neighbor solicitation was received, neighbor
   discovery would fail.  Now, we retry solicitation for some number of
   seconds before giving up.  Relatedly, the NDP implementation now takes
   the MAC address from Ethernet header if reply does not contain it in
   the payload.

 * Automatically flush JIT if there are too many ingress packet drops.
   When the snabb breathe cycle runs, it usually doesn't drop any
   packets: packets pulled into the network are fully pushed through,
   with no residual data left in link buffers. However if the breathe()
   function takes too long, it's possible for it to miss incoming
   packets deposited in ingress ring buffers. That is usually the source
   of packet loss in a Snabb program.

   There are several things that can cause packet loss: the workload
   taking too long on average, and needing general optimization; the
   workload taking too long, but only during some fraction of breaths,
   for example due to GC or other sources of jitter; or, the workload
   was JIT-compiled with one incoming traffic pattern, but conditions
   have changed meaning that the JIT should re-learn the new
   patterns. The ingress drop monitor exists to counter this last
   reason. If the ingress drop monitor detects that the program is
   experiencing ingress drop, it will call jit.flush(), to force LuaJIT
   to re-learn the paths that are taken at run-time. It will avoid
   calling jit.flush() too often, in the face of sustained packet loss,
   by default flushing the JIT only once every 20 seconds.

 * Bug-fix backports from upstream Snabb: fix bugs when trying to use
   PCI devices whose names contain hexadecimal characters (from Pete
   Bristow), and include some documentation on performance tuning (by
   Marcel Wiget).

 * The load tester now works on line bitrates, including the ethernet
   protocol overhead (interframe spacing, prologues, and so on).

 * Add --cpu argument to "snabb lwaftr run", to set CPU affinity.  You
   can use --cpu instead of using "taskset", if you like.

 * Add --real-time argument to "snabb lwaftr run", to enable real-time
   scheduling.  This might be useful when troubleshooting, though in
   practice we have found that it does not have a significant effect on
   scheduling jitter, as the CPU affinity largely prevents the kernel
   from upsetting a Snabb process.

## [2.3] - 2016-02-17

A bug fix and performance improvement release.

 * Fix case in which TTL of ICMPv4 packets was not always being
   decremented.

 * Fix memory leaks when dropping packets due to 0 TTL, failed binding
   table lookup, or other errors that might cause ICMP error replies.

 * Fix hairpinning of ICMP error messages for non-existent IPv4 hosts.
   Before, these errors always were going out the public IPv4 interface
   instead of being hairpinned if needed.

 * Fix hairpinning of ICMP error messages for incoming IPv4 packets
   whose TTL is 0 or 1. Before, these errors always were going out the
   public IPv4 interface instead of being hairpinned if needed.

 * Fix hairpinning of ICMP error messages for packets with the DF bit
   that would cause fragmentation. Likewise these were always going out
   the public interface.

 * Allow B4s that have access to port 0 on their IPv4 address to be
   pinged from the internet or from a hairpinned B4, and to reply.  This
   enables a B4 with a whole IPv4 address to be pinged.  Having any
   reserved ports on an IPv4 address will prevent any B4 on that IPv4
   from being pinged, as reserved ports make port 0 unavailable.

 * Switch to stream in results from binding table lookups in batches of
   32 using optimized assembly code.  This increases performance
   substantially.

## [2.2] - 2016-02-11

Adds `--ring-buffer-size` argument to `snabb lwaftr run` which can
increase the receive queue size.  This won't solve packet loss when the
lwaftr is incapable of handling incoming throughput, but it might reduce
packet loss due to jitter in the `breathe()` times.  The default size is
512 packets; any power of 2 up to 32K is accepted.

Also, fix `snabb lwaftr run -v -v` (multiple `-v` options).  This will
periodically print packet loss statistics to the console.  This can
measure ingress packet loss as it is taken from the NIC counters.

## [2.1] - 2016-02-10

A bug-fix release to fix VLAN tagging/untagging when offloading this
operation to the 82599 hardware.

## [2.0] - 2016-02-09

A major release; see the documentation at
https://github.com/Igalia/snabb/tree/lwaftr_starfruit/src/program/lwaftr/doc
for more details on how to use all of these features.  Besides
bug-fixes, notable additions include:

 * Support for large binding tables with millions of softwires.  The
   binding table will be compiled to a binary format as needed, and may
   be compiled to a binary file ahead of time.

 * The configuration file syntax and the binding table syntax have
   changed once again.  We apologize for the inconvenience, but it
   really is for the better: now, address-sharing softwires can be
   specified directly using the PSID format.

 * Support for virtualized operation using `virtio-net`.

 * Support for discovery of next-hop L2 addresses on the B4 side via
   neighbor discovery.

 * Support for ingress and egress filters specified in `pflang`, the
   packet filtering language of language of `tcpdump`.

 * Ability to reload the binding table via a `snabb lwaftr control`
   command.

## [1.2] - 2015-12-10

Fix bugs related to VLAN tagging on port-restricted IP addresses.

Fix bugs related to ICMPv6 and hairpinning.

## [1.1] - 2015-11-25

This release has breaking configuration file changes for VLAN tags and
MTU sizes; see details below.

This release fixes VLAN tagging for outgoing ICMP packets. Outgoing ICMP
worked without VLANs, and now also works with them. Incoming ICMP
support looked broken as a side effect of the outgoing ICMP messages
with VLAN tags translated by the lwAftr not being valid. The primary
test suite has been upgraded to be equally comprehensive with and
without vlan support.

This release contains fragmentation support improvements. It fixes a
leak in IPv6 fragmentation reassembly, and enables IPv4 reassembly. For
best performance, networks should be configured to avoid fragmentation
as much as possible.

This release also allows putting a ```debug = true,``` line into
configuration files (ie, the same file where vlan tags are
specified). If this is done, verbose debug information is shown,
including at least one message every time a packet is received. This
mode is purely for troubleshooting, not benchmarking.

*Please note that there are two incompatible changes to the
 configuration file format.*

Firstly, the format for specifying VLAN tags has changed incompatibly.
Instead of doing:

```
v4_vlan_tag=C.htonl(0x81000444),
v6_vlan_tag=C.htonl(0x81000666),
```

the new format is:

```
v4_vlan_tag=0x444,
v6_vlan_tag=0x666,
```

We apologize for the inconvenience.

Secondly, the way to specify MTU sizes has also changed incompatibly.
Before, the `ipv4_mtu` and `ipv6_mtu` implicitly included the size for
the L2 header; now they do not, instead only measuring the packet size
from the start of the IPv4 or IPv6 header, respectively.

## [1.0] - 2015-10-01

### Added

- Static configuration of the provisioned set of subscribers and their mapping
to IPv4 addresses and port ranges from a text file (binding table).
- Static configuration of configurable options from a text file (lwaftr.conf).
- Feature-complete encapsulation and decapsulation of IPv4-in-IPv6.
- ICMPv4 handling: configurable as per RFC7596.
- ICMPv6 handling, as per RFC 2473.
- Feature-complete tunneling and traffic class mapping, with first-class support
for IPv4 packets containing UDP, TCP, and ICMP, as per RFCs 6333, 2473 and 2983.
- Feature-complete configurable error handling via ICMP messages, for example 
"destination unreachable", "host unreachable", "source address failed 
ingress/egress filter", and so on as specified.
- Association of multiple IPv6 addresses for an lwAFTR, as per draft-farrer-
softwire-br-multiendpoints.
- Full fragmentation handling, as per RFCs 6333 and 2473.
- Configurable (on/off) hairpinning support for B4-to-B4 packets.
- A static mechanism for rate-limiting ICMPv6 error messages.
- 4 million packets per second (4 MPPS) in the following testing configuration:
   - Two dedicated 10G NICs: one internet-facing and one subscriber facing (2 MPPS per NIC)
   - 550-byte packets on average.
   - A small binding table.
   - "Download"-like traffic that stresses encapsulation speed
   - Unfragmented packets
   - Unvirtualized lwAFTR process
   - A single configured IPv6 lwAFTR address.
- Source:
   - apps/lwaftr: Implementation of the lwAFTR.
- Programs:
   - src/program/snabb_lwaftr/bench: Used to get an idea of the raw speed of the
lwaftr without interaction with NICs
   - src/program/snabb_lwaftr/check: Used in the lwAFTR test suite. 
   - src/program/snabb_lwaftr/run: Runs the lwAFTR.
   - src/program/snabb_lwaftr/transient: Transmits packets from a PCAP-FILE to 
the corresponding PCI network adaptors. Starts at zero bits per second, ramping 
up to BITRATE bits per second in increments of STEP bits per second.
- Tests:
   - src/program/tests:
      - end-to-end/end-to-end.sh: Feature tests.
      - data: Different data samples, binding tables and lwAFTR configurations.
      - benchdata: Contains IPv4 and IPv6 pcap files of different sizes.
