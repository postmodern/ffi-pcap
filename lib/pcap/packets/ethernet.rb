require 'pcap/packets/typedefs'
require 'pcap/mac_addr'
require 'pcap/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      class Ethernet < FFI::Struct

        include Packet

        # Size of an Ethernet header
        SIZE = 14

        layout :ether_dhost, MACAddr,
               :ether_shost, MACAddr,
               :ether_type, :ushort

        #
        # Returns the source MAC address.
        #
        def src_mac
          self[:ether_shost]
        end

        #
        # Returns the destination MAC address.
        #
        def dest_mac
          self[:ether_dhost]
        end

      end
    end
  end
end
