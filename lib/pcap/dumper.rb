require 'pcap/ffi'

require 'ffi'

module FFI
  module PCap
    class Dumper < FFI::MemoryPointer

      def initialize(dumper)
        @dumper = dumper
      end

      def tell
        PCap.pcap_dump_ftell(@dumper)
      end

      def flush
        PCap.pcap_dump_flush(@dumper)
      end

      def close
        PCap.pcap_dump_close(@dumper)
      end

      def to_ptr
        @dumper
      end

      def inspect
        "#<#{self.class}: 0x#{@dumper.address.to_s(16)}>"
      end

    end
  end
end
