require 'pcap/packets/typedefs'
require 'pcap/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      class TCP < FFI::Struct

        include Packet

        # TCP flags
        FLAGS = [
          # Null flags
          NULL = 0x00,

          # Final packet flag
          FIN = 0x01,

          # Synchronization packet flag
          SYN = 0x02,

          # Reset packet flag
          RST = 0x04,

          # Push packet flag
          PUSH = 0x08,

          # Acknowledgement packet flag
          ACK = 0x10,

          # Urgent data packet flag
          URG = 0x20,

          # ECE packet flag
          ECE = 0x40,

          # CWR packet flag
          CWR = 0x80,

          # All combined flags
          XMAS = (FIN | SYN | RST | PUSH | ACK | URG | ECE | CWR)
        ]

        layout :th_sport, :uint16,
               :th_dport, :uint16,
               :th_seq, :tcp_seq,
               :th_ack, :tcp_seq,
               :th_offx2, :uint8,
               :th_flags, :uint8,
               :th_win, :uint16,
               :th_sum, :uint16,
               :th_urp, :uint16

        #
        # Returns the source port.
        #
        def src_port
          self[:th_sport]
        end

        #
        # Returns the destination port.
        #
        def dest_port
          self[:th_dport]
        end

        #
        # Returns the sequence number of the packet.
        #
        def seq
          self[:th_seq]
        end

        #
        # Returns the acknowledgement number of the packet.
        #
        def ack
          self[:th_ack]
        end

        #
        # Returns the data offset for the packet.
        #
        def offset
          (self[:th_offx2] & 0xf0) >> 4
        end

        #
        # Returns +true+ if the packet has no flags set, +false+ otherwise.
        #
        def null?
          self[:th_flags] == NULL
        end

        #
        # Returns +true+ if the packet has the FIN flag set, returns
        # +false+ otherwise.
        #
        def fin?
          (self[:th_flags] & FIN) != 0
        end

        #
        # Returns +true+ if the packet has the SYN flag set, returns
        # +false+ otherwise.
        #
        def syn?
          (self[:th_flags] & SYN) != 0
        end

        #
        # Returns +true+ if the packet has the RST flag set, returns
        # +false+ otherwise.
        #
        def rst?
          (self[:th_flags] & RST) != 0
        end

        #
        # Returns +true+ if the packet has the PUSH flag set, returns
        # +false+ otherwise.
        #
        def push?
          (self[:th_flags] & PUSH) != 0
        end

        #
        # Returns +true+ if the packet has the ACK flag set, returns
        # +false+ otherwise.
        #
        def ack?
          (self[:th_flags] & ACK) != 0
        end

        #
        # Returns +true+ if the packet has the URG flag set, returns
        # +false+ otherwise.
        #
        def urg?
          (self[:th_flags] & URG) != 0
        end

        #
        # Returns +true+ if the packet has the ECE flag set, returns
        # +false+ otherwise.
        #
        def ece?
          (self[:th_flags] & ECE) != 0
        end

        #
        # Returns +true+ if the packet has the CWR flag set, returns
        # +false+ otherwise.
        #
        def cwr?
          (self[:th_flags] & CWR) != 0
        end

        #
        # Returns +true+ if the packet has all flags set, +false+ otherwise.
        #
        def xmas?
          (self[:th_flags] & XMAS) == XMAS
        end

      end
    end
  end
end
