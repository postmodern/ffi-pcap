
module FFI
  module PCap
    class Handler

      include Enumerable

      # Default snaplen
      SNAPLEN = 65535

      # Pointer to the pcap opaque type
      attr_reader :pcap

      def initialize(pcap, options={})
        @pcap = pcap

        @closed = false

        @errbuf = ErrorBuffer.new

        if options[:direction]
          self.direction = options[:direction]
        end

        trap('SIGINT', &method(:close))
        trap('SIGTERM', &method(:close))

        yield self if block_given?
      end

      # Get the format version of an opened pcap savefile. 
      # XXX If this is a live capture, the values returned are not meaningful.
      def cap_version
        "#{PCap.pcap_major_version(@pcap)}.#{PCap.pcap_minor_version(@pcap)}"
      end

      def direction=(dir)
        dirs = PCap.enum_type(:pcap_direction_t)
        ret = PCap.pcap_setdirection(@pcap, dirs[:"pcap_d_#{dir}"]) == 0
        if ret == 0
          return true
        else
          raise(LibError, geterr(), caller)
        end
      end


      def datalink
        @datalink ||= DataLink.new(PCap.pcap_datalink(pcap))
      end

      def non_blocking=(mode)
        mode = if mode
          1
        else
          0
        end

        if PCap.pcap_setnonblock(@pcap, mode, @errbuf) == -1
          raise(LibError, @errbuf.to_s, caller)
        end

        return mode == 1
      end

      def non_blocking?
        mode = PCap.pcap_getnonblock(@pcap, @errbuf)

        if mode == -1
          raise(LibError, @errbuf.to_s, caller)
        end

        return mode == 1
      end


      # @yield [this, pkt, tag] 
      # @yieldparam [self] this
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      # @yieldparam [tag, nil] 
      #   A reference to the tag is passed if one was supplied with opts[:tag].
      #
      def loop(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_loop(@pcap, cnt, _wrap_callback(&block), opts[:tag])
        if ret == -1
          raise(ReadError, geterr(), caller)
        elsif ret -2
          return nil
        elsif ret > -1
          return ret
        else
          raise(ReadError, "unexpected return from pcap_loop(): #{ret}")
        end
      end

      alias each loop


      # @yield [this, pkt, tag] 
      # @yieldparam [self] this
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      # @yieldparam [tag, nil] 
      #   A reference to the tag is passed if one was supplied with opts[:tag].
      def dispatch(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_dispatch(@pcap, cnt, _wrap_callback(&block), o[:tag])
        if ret == -1
          raise(ReadError, geterr(), caller)
        elsif ret -2
          return nil
        elsif ret > -1
          return ret
        else
          raise(ReadError, "unexpected return from pcap_dispatch(): #{ret}")
        end
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
          return nil
        when 1
          hdr = PacketHeader.new( hdr_p.get_pointer(0) )
          return Packet.new(hdr, buf_p)
        end
      end

      def open_dump(path)
        dump_ptr = PCap.pcap_dump_open(@pcap, File.expand_path(path))

        if dump_ptr.null?
          raise(LibError, geterr(), caller)
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

      private
        def _wrap_callback(&block)
          lambda {|u, h, b| block.call(self, Packet.new(h, b), u) }
        end


    end

    callback :pcap_handler, [:pointer, PacketHeader, :pointer], :void

    attach_function :pcap_close, [:pcap_t], :void

    attach_function :pcap_loop, [:pcap_t, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_dispatch, [:pcap_t, :int, :pcap_handler, :pointer], :int

    attach_function :pcap_next, [:pcap_t, PacketHeader], :pointer
    attach_function :pcap_next_ex, [:pcap_t, :pointer, :pointer], :int
    attach_function :pcap_breakloop, [:pcap_t], :void
    attach_function :pcap_stats, [:pcap_t, Stat], :int
    attach_function :pcap_setfilter, [:pcap_t, BPFProgram], :int
    attach_function :pcap_setdirection, [:pcap_t, :pcap_direction_t], :int
    attach_function :pcap_getnonblock, [:pcap_t, :pointer], :int
    attach_function :pcap_setnonblock, [:pcap_t, :int, :pointer], :int
    attach_function :pcap_perror, [:pcap_t, :string], :void
    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_compile_nopcap, [:int, :int, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_freecode, [BPFProgram], :void
    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pcap_t, :pointer], :int
    attach_function :pcap_set_datalink, [:pcap_t, :int], :int

    attach_function :pcap_snapshot, [:pcap_t], :int
    attach_function :pcap_is_swapped, [:pcap_t], :int

    attach_function :pcap_dump_open, [:pcap_t, :string], :pcap_dumper_t

    attach_function :pcap_major_version, [:pcap_t], :int
    attach_function :pcap_minor_version, [:pcap_t], :int


    # XXX not sure if we even want FILE io stuff yet (or ever).

    #attach_function :pcap_fopen_offline, [:FILE, :pointer], :pcap_t
    #attach_function :pcap_file, [:pcap_t], :FILE
    #attach_function :pcap_dump_fopen, [:pcap_t, :FILE], :pcap_dumper_t
    #attach_function :pcap_fileno, [:pcap_t], :int

  end
end
