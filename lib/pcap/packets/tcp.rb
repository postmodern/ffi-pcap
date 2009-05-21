require 'pcap/packets/typedefs'

require 'ffi'

module FFI
  module PCap
    module Packets
      class TCP < FFI::Struct

        FLAGS = [
          FIN = 0x01,
          SYN = 0x02,
          RST = 0x04,
          PUSH = 0x08,
          ACK = 0x10,
          URG = 0x20,
          ECE = 0x40,
          CWR = 0x80,
          XMAS = (FIN | SYN | RST | PUSH | ACK | URG | ECE | CWR)
        ]

        layout :th_sport, :ushort,
               :th_dport, :ushort,
               :th_seq, :tcp_seq,
               :th_ack, :tcp_seq,
               :th_offx2, :uchar,
               :th_flags, :uchar,
               :th_win, :ushort,
               :th_sum, :ushort,
               :th_urp, :ushort

        def src_port
          self[:th_sport]
        end

        def dest_port
          self[:th_dport]
        end

        def seq
          self[:th_seq]
        end

        def ack
          self[:th_ack]
        end

        def acked?(num)
          self[:th_ack] == num
        end

        def offset
          (self[:th_offx2] & 0xf0) >> 4
        end

        def fin?
          (self[:th_flags] & FIN) != 0
        end

        def syn?
          (self[:th_flags] & SYN) != 0
        end

        def rst?
          (self[:th_flags] & RST) != 0
        end

        def push?
          (self[:th_flags] & PUSH) != 0
        end

        def ack?
          (self[:th_flags] & ACK) != 0
        end

        def urg?
          (self[:th_flags] & URG) != 0
        end

        def ece?
          (self[:th_flags] & ECE) != 0
        end

        def cwr?
          (self[:th_flags] & CWR) != 0
        end

      end
    end
  end
end
