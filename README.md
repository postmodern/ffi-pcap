# ffi-pcap

* [github.com/sophsec/ffi-pcap](http://github.com/sophsec/ffi-pcap/)
* [github.com/sophsec/ffi-pcap/issues](http://github.com/sophsec/ffi-pcap/issues)
* Postmodern (postmodern.mod3 at gmail.com)
* Eric Monti (esmonti at gmail.com)

## Description

Ruby FFI bindings for libpcap.

## Features

Exposes all features of the libpcap library including live packet capture, 
offline packet capture, live packet injection, etc..

Currently, FFI::PCap does _not_ supply any packet dissection routines. 
The choice of what to use is left up to you.

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


## Requirements

* [libpcap](http://www.tcpdump.org/) or [winpcap](http://winpcap.org/)
* [ffi](http://github.com/ffi/ffi) ~> 0.6.0
* [ffi_dry](http://github.com/emonti/ffi_dry) ~> 0.1.9

## Install

    $ sudo gem install ffi-pcap

## License

See {file:LICENSE.txt} for license information.

