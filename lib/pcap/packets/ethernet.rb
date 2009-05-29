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

        def is_pup?
          self[:ether_type] == PUP_TYPE
        end

        def is_sprite?
          self[:ether_type] == SPRITE_TYPE
        end

        def is_ip?
          self[:ether_type] == IP_TYPE
        end

        def is_arp?
          self[:ether_type] == ARP_TYPE
        end

        def is_rarp?
          self[:ether_type] == RARP_TYPE
        end

        def is_apple_talk?
          self[:ether_type] == APPLE_TALK_TYPE
        end

        def is_aarp?
          self[:ether_type] == AARP_TYPE
        end

        def is_vlan?
          self[:ether_type] == VLAN_TYPE
        end

        def is_ipx?
          self[:ether_type] == IPX_TYPE
        end

        def is_ipv6?
          self[:ether_type] == IPV6_TYPE
        end

        def is_loopback?
          self[:ether_type] == LOOPBACK_TYPE
        end

      end
    end
  end
end
