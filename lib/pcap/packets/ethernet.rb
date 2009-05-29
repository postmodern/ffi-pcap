require 'pcap/packets/typedefs'
require 'pcap/mac_addr'
require 'pcap/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      class Ethernet < FFI::Struct

        include Packet

        PUP = 0x0200             # Xerox PUP
        SPRITE = 0x0500          # Sprite
        IP = 0x0800              # IP
        ARP = 0x0806             # Address Resolution Protocol
        RARP = 0x8035            # Reverse ARP
        APPLE_TALK = 0x809b      # AppleTalk protocol
        AARP = 0x80f3            # AppleTalk ARP
        VLAN = 0x8100            # IEEE 802.1Q VLAN tagging
        IPX = 0x8137             # IPX
        IPV6 = 0x86dd            # IP protocol version 6
        LOOPBACK = 0x9000        # used to test interfaces

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
          self[:ether_type] == PUP
        end

        def is_sprite?
          self[:ether_type] == PUP
        end

        def is_ip?
          self[:ether_type] == IP
        end

        def is_arp?
          self[:ether_type] == ARP
        end

        def is_rarp?
          self[:ether_type] == RARP
        end

        def is_apple_talk?
          self[:ether_type] == APPLE_TALK
        end

        def is_aarp?
          self[:ether_type] == AARP
        end

        def is_vlan?
          self[:ether_type] == VLAN
        end

        def is_ipx?
          self[:ether_type] == IPX
        end

        def is_ipv6?
          self[:ether_type] == IPV6
        end

        def is_loopback?
          self[:ether_type] == IPV6
        end

      end
    end
  end
end
