module FFI
  module PCap
    #
    # See pcap_dumper_t in pcap.h
    #
    # A pcap_dumper, or FFI::PCap::Dumper is handled opaquely so that it can
    # be implemented differently on different platforms. In FFI::PCap, we
    # simply wrap the pcap_dumper_t pointer with a ruby interface.
    #
    class Dumper

      def initialize(dumper)
        @dumper = dumper
      end

      def _write(header, bytes)
        FFI::PCap.pcap_dump(@dumper, header, bytes)
      end

      def write(*args)
        if args.first.is_a? Packet
          write_pkt(*args)
        else
          _write(*args)
        end
      end

      def write_pkt(pkt)
        _write(pkt.header, pkt.body_ptr)
      end

      def tell
        FFI::PCap.pcap_dump_ftell(@dumper)
      end

      def flush
        FFI::PCap.pcap_dump_flush(@dumper)
      end

      def close
        FFI::PCap.pcap_dump_close(@dumper)
      end

    end

    # XXX not sure if we even want file FILE IO stuff yet
    #attach_function :pcap_dump_file, [:pcap_dumper_t], :FILE

    attach_function :pcap_dump_ftell, [:pcap_dumper_t], :long
    attach_function :pcap_dump_flush, [:pcap_dumper_t], :int
    attach_function :pcap_dump_close, [:pcap_dumper_t], :void
    attach_function :pcap_dump, [:pointer, PacketHeader, :pointer], :void

  end
end
