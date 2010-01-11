
require 'ffi'

module FFI
  module PCap
    class Handler

      include Enumerable

      # Default snaplen
      SNAPLEN = 65535

      # Pointer to the pcap opaque type
      attr_reader :pcap

      # DataLink for the pcap descriptor
      attr_reader :datalink

      def initialize(pcap, options={})
        @pcap = pcap
        @datalink = DataLink.new(PCap.pcap_datalink(@pcap))

        @closed = false

        if options[:direction]
          self.direction = options[:direction]
        end

        trap('SIGINT', &method(:close))
        trap('SIGTERM', &method(:close))
      end


      def direction=(dir)
        dirs = PCap.enum_type(:pcap_direction_t)
        ret = PCap.pcap_setdirection(@pcap, dirs[:"pcap_d_#{dir}"]) == 0
        if ret == 0
          return true
        else
          raise(StandardError, geterr(), caller)
        end
      end


      def non_blocking=(mode)
        errbuf = ErrorBuffer.new
        mode = if mode
          1
        else
          0
        end

        if PCap.pcap_setnonblock(@pcap, mode, errbuf) == -1
          raise(RuntimeError, errbuf.to_s, caller)
        end

        return mode == 1
      end

      def non_blocking?
        errbuf = ErrorBuffer.new
        mode = PCap.pcap_getnonblock(@pcap, errbuf)

        if mode == -1
          raise(RuntimeError, errbuf.to_s, caller)
        end

        return mode == 1
      end

      def wrap_callback(&block)
        lambda {|u, h, b| block.call(u, Packet.new(h, b)) }
      end

      def loop(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_loop(@pcap, cnt, wrap_callback(&block), opts[:tag])
      end

      alias each loop

      def dispatch(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_dispatch(@pcap, cnt, wrap_callback(&block), o[:tag])
      end

      def next
        header = PacketHeader.new
        bytes = PCap.pcap_next(@pcap, header)

        if bytes.null?
          return nil # or raise an exception?
        else
          return Packet.new(header, bytes)
        end
      end

      def next_extra
        hdr_p = MemoryPointer.new(:pointer)
        buf_p = MemoryPointer.new(:pointer)

        case PCap.pcap_next_ex(@pcap, hdr_p, buf_p)
        when 0
          raise(ReadError, "the timeout expired", caller)
        when -1
          raise(ReadError, geterr(), caller)
        when -2
          raise(ReadError, "the 'savefile' contains no more packets", caller)
        when 1
          hdr = PacketHeader.new( hdr_p.get_pointer(0) )
          return Packet.new(hdr, buf_p)
        end

      end

      def open_dump(path)
        dump_ptr = PCap.pcap_dump_open(@pcap, File.expand_path(path))

        if dump_ptr.null?
          raise(RuntimeError, geterr(), caller)
        end

        return Dumper.new(dump_ptr)
      end

      def stats
        stats = Stat.new

        PCap.pcap_stats(@pcap, stats)
        return stats
      end

      def geterr
        PCap.pcap_geterr(@pcap)
      end

      alias error geterr

      def stop
        PCap.pcap_breakloop(@pcap)
      end

      def closed?
        @closed == true
      end

      def close
        unless @closed
          @closed = true
          PCap.pcap_close(@pcap)
        end
      end

      def to_ptr
        @pcap
      end

      def inspect
        "#<#{self.class}: 0x#{@pcap.address.to_s(16)}>"
      end

    end
  end
end
