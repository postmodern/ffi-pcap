require 'pcap/packet'
require 'pcap/in_addr'

require 'ffi'

module FFI
  module PCap
    module Packets
      class IPv4 < FFI::Struct

        include Packet

        # IPv4 flags
        FLAGS = [
          # Reserved fragment flag
          RESERVED_FRAGMENT = 0x8000,

          # Dont fragment flag
          DONT_FRAGMENT = 0x4000,

          # More fragments flag
          MORE_FRAGMENTS = 0x2000
        ]

        # Mask for fragment flags
        FRAGMENT_MASK = 0x1fff
        
        layout :ip_vhl, :uint8,
               :ip_tos, :uint8,
               :ip_len, :uint16,
               :ip_id, :uint16,
               :ip_off, :uint16,
               :ip_ttl, :uint8,
               :ip_p, :uint8,
               :ip_sum, :uint16,
               :ip_src, InAddr,
               :ip_dst, InAddr

        #
        # Returns the version of the IP packet.
        #
        def version
          self[:ip_vhl] >> 4
        end

        #
        # Returns the header length of the packet.
        #
        def header_length
          self[:ip_vhl] & 0x0f
        end

        #
        # Returns the Type of Service (TOS).
        #
        def tos
          self[:ip_tos]
        end

        #
        # Returns the total packet length.
        #
        def packet_length
          self[:ip_len]
        end

        #
        # Returns the packet id.
        #
        def id
          self[:ip_id]
        end

        #
        # Returns the fragment offset.
        #
        def offset
          self[:ip_off]
        end

        #
        # Returns the Time to Live (TTL).
        #
        def ttl
          self[:ip_ttl]
        end

        #
        # Returns the protocol number.
        #
        def protocol
          self[:ip_p]
        end

        #
        # Returns the packet checksum.
        #
        def checksum
          self[:ip_sum]
        end

        #
        # Returns the source IP address.
        #
        def src
          self[:ip_src]
        end

        #
        # Returns the destination IP address.
        #
        def dest
          self[:ip_dest]
        end

      end
    end
  end
end
