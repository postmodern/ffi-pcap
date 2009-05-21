require 'pcap/in_addr'

require 'ffi'

module FFI
  module PCap
    module Packets
      class IPv4 < FFI::Struct

        FLAGS = [
          RESERVED_FRAGMENT = 0x8000,
          DONT_FRAGMENT = 0x4000,
          MORE_FRAGMENTS = 0x2000
        ]

        FRAGMENT_MASK = 0x1fff
        
        layout :ip_vhl, :uchar,
               :ip_tos, :uchar,
               :ip_len, :ushort,
               :ip_id, :ushort,
               :ip_off, :ushort,
               :ip_ttl, :uchar,
               :ip_p, :uchar,
               :ip_sum, :ushort,
               :ip_src, InAddr,
               :ip_dst, InAddr

        def version
          self[:ip_vhl] >> 4
        end

        def header_length
          self[:ip_vhl] & 0x0f
        end

        def tos
          self[:ip_tos]
        end

        def packet_length
          self[:ip_len]
        end

        def id
          self[:ip_id]
        end

        def offset
          self[:ip_off]
        end

        def ttl
          self[:ip_ttl]
        end

        def protocol
          self[:ip_p]
        end

        def checksum
          self[:ip_sum]
        end

        def src
          self[:ip_src]
        end

        def dest
          self[:ip_dest]
        end

      end
    end
  end
end
