require 'pcap/packets/typedefs'
require 'pcap/mac_addr'
require 'pcap/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      class Ethernet < FFI::Struct

        include Packet

        PUP_TYPE = 0x0200             # Xerox PUP
        SPRITE_TYPE = 0x0500          # Sprite
        XNS_TYPE = 0x0600             # XNS
        IP_TYPE = 0x0800              # IP
        ARP_TYPE = 0x0806             # Address Resolution Protocol
        RARP_TYPE = 0x8035            # Reverse ARP
        APPLE_TALK_TYPE = 0x809b      # AppleTalk protocol
        AARP_TYPE = 0x80f3            # AppleTalk ARP
        VLAN_TYPE = 0x8100            # IEEE 802.1Q VLAN tagging
        IPX_TYPE = 0x8137             # IPX
        IPV6_TYPE = 0x86dd            # IP protocol version 6
        LOOPBACK_TYPE = 0x9000        # used to test interfaces

        # Size of an Ethernet header
        SIZE = 14

        layout :ether_dhost, MACAddr,
               :ether_shost, MACAddr,
               :ether_type, [NativeType::UINT8, 2]

        def type
          self[:ether_type].to_endian(:big)
        end

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

        def pup?
          self.type == PUP_TYPE
        end

        def sprite?
          self.type == SPRITE_TYPE
        end

        def xns?
          self.type == XNS_TYPE
        end

        def ip?
          self.type == IP_TYPE
        end

        def arp?
          self.type == ARP_TYPE
        end

        def rarp?
          self.type == RARP_TYPE
        end

        def apple_talk?
          self.type == APPLE_TALK_TYPE
        end

        def aarp?
          self.type == AARP_TYPE
        end

        def vlan?
          self.type == VLAN_TYPE
        end

        def ipx?
          self.type == IPX_TYPE
        end

        def ipv6?
          self.type == IPV6_TYPE
        end

        def loopback?
          self.type == LOOPBACK_TYPE
        end

      end
    end
  end
end
