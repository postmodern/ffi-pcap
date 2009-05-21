require 'pcap/ffi'

require 'ffi'

module FFI
  module PCap
    class Dumper < FFI::MemoryPointer

      def self.open(path)
      end

      def tell
        PCap.pcap_dump_ftell(self)
      end

      def flush
        PCap.pcap_dump_flush(self)
      end

      def close
        PCap.pcap_dump_close(self)
      end

    end
  end
end
