# ffi-pcap

* [Source](https://github.com/sophsec/ffi-pcap/)
* [Issues](https://github.com/sophsec/ffi-pcap/issues)
* [Documentation](http://rubydoc.info/gems/ffi-pcap/frames)
* Postmodern (postmodern.mod3 at gmail.com)
* Eric Monti (esmonti at gmail.com)

## Description

Ruby FFI bindings for libpcap.

## Features

Exposes all features of the libpcap library including live packet capture, 
offline packet capture, live packet injection, etc..

Currently, FFI::PCap does _not_ supply any packet dissection routines. 
The choice of what to use is left up to you.

Packet dissection libraries:

* [ffi-packets] - Maps raw packets to `FFI::Struct` objects.

## Examples

Reading ICMP packets from a live interface.

    require 'rubygems'
    require 'ffi/pcap'

    pcap =
      FFI::PCap::Live.new(:dev => 'lo0',
                          :timeout => 1,
                          :promisc => true,
                          :handler => FFI::PCap::Handler)

    pcap.setfilter("icmp")

    pcap.loop() do |this,pkt|
      puts "#{pkt.time}:"

      pkt.body.each_byte {|x| print "%0.2x " % x }
      putc "\n"
    end

Reading packets from a pcap dump file:

    require 'rubygems'
    require 'ffi/pcap'

    pcap = FFI::PCap::Offline.new("./foo.cap")

    pcap.loop() do |this,pkt|
      puts "#{pkt.time}:"

      pkt.body.each_byte {|x| print "%0.2x " % x }
      putc "\n"
    end

Replaying packets from a pcap dump file on a live interface:

    require 'rubygems'
    require 'ffi/pcap'

    live = FFI::PCap::Live.new(:device => 'en0')
    offline = FFI::PCap::Offline.new("./foo.cap")

    if live.datalink == offline.datalink
      offline.loop() {|this,pkt| live.inject(pkt) }
    end

## Requirements

* [libpcap] or [winpcap] >= 1.0.0
* [ffi] ~> 0.6.0
* [ffi_dry] ~> 0.1.9

## Install

    $ sudo gem install ffi-pcap

## License

See {file:LICENSE.txt} for license information.

[libpcap]: http://www.tcpdump.org/
[winpcap]: http://winpcap.org/

[ffi]: https://github.com/ffi/ffi#readme
[ffi_dry]: https://github.com/emonti/ffi_dry#readme
[ffi-packets]: http://github.com/emonti/ffi-packets#readme
