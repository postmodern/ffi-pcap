require 'pcap/typedefs'
require 'pcap/time_val'

require 'ffi/struct'

module FFI
  module PCap
    class PacketHeader < FFI::Struct
      layout :ts, TimeVal,
             :caplen, :bpf_uint32,
             :len, :bpf_uint32

      def timestamp
        self[:ts]
      end

      def captured
        self[:caplen]
      end

      def length
        self[:len]
      end
    end
  end
end
