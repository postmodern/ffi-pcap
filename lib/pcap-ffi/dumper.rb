
module FFI
  module PCap

    # See pcap_dumper_t in pcap.h
    #
    # A pcap_dumper, or PCap::Dumper is handled opaquely so that it can
    # be implemented differently on different platforms. In FFI::PCap, we
    # simply handle this as an opaque FFI::MemoryPointer with added 
    # helper methods.
    class Dumper < FFI::MemoryPointer

      def initialize(dumper)
        @dumper = dumper
      end

      def write(header,bytes)
        PCap.pcap_dump(@dumper,header,bytes)
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
