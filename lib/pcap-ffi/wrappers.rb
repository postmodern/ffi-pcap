module FFI
  module PCap

    # An abstract base wrapper class with features common to all pcap
    # device types. Do not use this directly, but use the corresponding
    # LiveWrapper, DeadWrapper, or FileWrapper class if you use
    # open_live, open_dead, or open_file respectively.
    class CommonWrapper

      attr_accessor :pcap

      def initialize(pcap, opts={})
        @pcap = pcap
        @closed = false
        @errbuf = ErrorBuffer.create

        trap('INT') {|s| stop(); close(); raise(SignalException, s)}
        trap('TERM') {|s| stop(); close(); raise(SignalException, s)}

        if block_given?
          yield self
          self.close()
        end
      end


      # Returns the DataLink for the pcap device.
      def datalink
        @datalink ||= DataLink.new(PCap.pcap_datalink(_pcap))
      end


      # Returns an array of supported DataLinks for the pcap device.
      def supported_datalinks
        dlt_lst = FFI::MemoryPointer.new(:pointer)
        if (cnt=PCap.pcap_list_datalinks(_pcap, dlt_lst)) < 0
          raise(LibError, "pcap_list_datalinks(): #{geterr()}")
        end
        # extract datalink values 
        p = dlt_lst.get_pointer(0)
        ret = p.get_array_of_int(0, cnt).map {|dlt| DataLink.new(dlt) }
        PCap.free(p)
        return ret
      end

      # Indicates whether the pcap interface is already closed.
      def closed?
        @closed == true
      end

      # Closes the pcap interface using libpcap.
      def close
        unless @closed
          @closed = true
          PCap.pcap_close(_pcap)
        end
      end

      # Returns the pcap interface pointer.
      #
      # @return [FFI::Pointer]
      #   Internal pointer to a pcap_t handle.
      #
      def to_ptr
        _check_pcap()
      end
      
      # Gets the snapshot length.
      #
      # @return [Integer]
      #  Snapshot length for the pcap interface.
      def snaplen
        PCap.pcap_snapshot(_pcap)
      end

      # Used to specify a pcap filter for the pcap interface. This method 
      # compiles a filter expression and applies it on the wrapped pcap 
      # interface.
      #
      # @param [String] expression
      #   A pcap filter expression. See pcap-filter(7) manpage for syntax.
      #
      # @options [Hash] opts
      #   Compile options. See compile()
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error message 
      #   from libpcap.
      #
      def set_filter(expression, opts={})
        code = compile(expression, opts)
        ret = PCap.pcap_setfilter(_pcap, code)
        code.free!  # done with this, we can free it
        raise(LibError, "pcap_setfilter(): #{geterr()}") if ret < 0
        return expression
      end

      alias setfilter set_filter
      alias filter= set_filter


      # Compiles a pcap filter but does not apply it to the pcap interface.
      #
      # @param [String] expression
      #   A pcap filter expression. See pcap-filter(7) manpage for syntax.
      #
      # @options [Hash] opts
      #   Additional options for compile
      #
      # @option opts [optional, Integer] :optimize
      #   Optimization flag. 0 means don't optimize. Defaults to 1.
      #
      # @option opts [optional, Integer] :netmask
      #   A 32-bit number representing the IPv4 netmask of the network on which
      #   packets are being captured. It is only used when checking for IPv4
      #   broadcast addresses in the filter program. Default: 0 (unspecified 
      #   netmask)
      #
      # @return [BPFProgram]
      #   A FFI::PCap::BPFProgram structure for the compiled filter.
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error message 
      #   from libpcap.
      #
      def compile(expression, opts={})
        optimize = opts[:optimize] || 1
        netmask  = opts[:netmask] || 0 
        code = BPFProgram.new
        if PCap.pcap_compile(_pcap, code, expression, optimize, netmask) < 0
          raise(LibError, "pcap_compile(): #{geterr()}")
        end
        return code
      end


      # @return [Dumper]
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error
      #   message from libpcap.
      #
      def open_dump(path)
        dp = PCap.pcap_dump_open(_pcap, File.expand_path(path))
        raise(LibError, "pcap_dump_open(): #{geterr()}", caller) if dp.null?
        return Dumper.new(dp)
      end


      # @return [String]
      #   The error text pertaining to the last pcap library error.
      #
      def geterr
        PCap.pcap_geterr(_pcap)
      end

      alias error geterr


      private
        # Raises an exception if @pcap is not set.
        #
        # Internal sanity check to confirm the pcap instance
        # variable has been set. Otherwise very bad things can 
        # ensue by passing a null pointer to various libpcap 
        # functions.
        def _check_pcap
          if @pcap.nil?
            raise(StandardError, "#{self.class} - nil pcap device")
          end
          @pcap
        end

        # Raises an exception if @pcap is not set or is a null pointer.
        #
        # Internal sanity check to confirm the pcap pointer
        # variable has been set and is not a null pointer. 
        # Otherwise very bad things can ensue by passing a null 
        # pointer to various libpcap functions.
        def _pcap
          if (p = _check_pcap()).null?
            raise(StandardError, "#{self.class} - null pointer to pcap device")
          end
          p
        end

    end

    # A wrapper class for pcap devices opened with open_dead()
    class DeadWrapper < CommonWrapper
      attr_reader :datalink

      def initialize(pcap, opts={}, &block)
        @datalink = opts[:datalink]

        super(pcap, opts, &block)
      end

    end

    # A superclass for both offline and live interfaces, but not dead interfaces
    # This class provides all the features necessary for working with packets.
    class CaptureWrapper < CommonWrapper
      include Enumerable

      # Processes packets from a live capture or savefile until cnt packets 
      # are processed, the end of the savefile is reached (when reading from a
      # savefile), pcap_breakloop() is called, or an error occurs. 
      #
      # It does not return when live read timeouts occur. A value of -1 or 0 
      # for cnt is equivalent to infinity, so that packets are processed until
      # another ending condition occurs.
      #
      # (In older versions of libpcap, the behavior when cnt was 0 was
      # undefined; different platforms and devices behaved differently, so
      # code that must work with older versions of libpcap should use -1, nor
      # 0, as the value of cnt.)
      #
      # @options [Hash] opts
      #
      # @yield [this, pkt, tag] 
      #
      # @yieldparam [self] this
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      # @yieldparam [tag, nil] 
      #   A reference to the tag is passed if one was supplied with opts[:tag].
      #
      # @return [Integer, nil]
      #   returns 0 if cnt is exhausted, or nil if the loop terminated due to
      #   a call to pcap_breakloop() before any packets were processed. It
      #   does not return when live read timeouts occur; instead, it attempts
      #   to read more packets.
      #
      # @raise [ReadError]
      #   An exception is raised if an error occurs or if libpcap returns
      #   an unexpected value.
      #
      def loop(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_loop(_pcap, cnt, _wrap_callback(&block), opts[:tag])
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


      # Processes packets from a live capture or savefile until cnt packets
      # are processed, the end of the current bufferful of packets is reached
      # when doing a live capture, the end of the savefile is reached (when
      # reading from a savefile), pcap_breakloop() is called, or an error
      # occurs. 
      # 
      # Thus, when doing a live capture, cnt is the maximum number of packets
      # to process before returning, but is not a minimum number; when reading
      # a live capture, only one bufferful of packets is read at a time, so
      # fewer than cnt packets may be processed. A value of -1 or 0 for cnt
      # causes all the packets received in one buffer to be processed when
      # reading a live capture, and causes all the packets in the file to be
      # processed when reading a savefile.
      # 
      # Note: In older versions of libpcap, the behavior when cnt was 0 was
      # undefined; different platforms and devices behaved differently, so
      # code that must work with older versions of libpcap should use -1, nor
      # 0, as the value of cnt.
      # 
      # @yield [this, pkt, tag] 
      #
      # @yieldparam [self] this
      #   A reference to self is passed to the block.
      #
      # @yieldparam [Packet] pkt
      #   A packet object is yielded which references the header and bytes.
      #
      # @yieldparam [tag, nil] 
      #   A reference to the tag is passed if one was supplied with opts[:tag].
      #
      # @return [Integer, nil]
      #   Returns the number of packets processed on success; this can be 0 if
      #   no packets were read from a live capture or if no more packets are
      #   available in a savefile. It returns nil if the loop terminated due 
      #   to a call to CommonWrapper.stop() before any packets were processed.
      #
      # @raise [ReadError]
      #   An exception is raised if an error occurs or if libpcap returns
      #   an unexpected value.
      #
      def dispatch(opts={}, &block)
        cnt = opts[:count] || -1 # default to infinite loop
        ret = PCap.pcap_dispatch(_pcap, cnt, _wrap_callback(&block), o[:tag])
        if ret == -1
          raise(ReadError, "pcap_dispatch(): #{geterr()}", caller)
        elsif ret -2
          return nil
        elsif ret > -1
          return ret
        else
          raise(ReadError, "unexpected return from pcap_dispatch() -> #{ret}")
        end
      end


      # This method uses the older pcap_next() function which has been
      # deprecated in favor of pcap_next_ex(). It is included only for
      # backward compatability purposes.
      #
      # Important Note. According to libpcap documentation: 
      #
      # Unfortunately, there is no way to determine whether an error 
      # occured or not when using pcap_next().
      #
      def old_next
        header = PacketHeader.new
        bytes = PCap.pcap_next(_pcap, header)
        if bytes.null?
          return nil # or raise an exception?
        else
          return Packet.new(header, bytes)
        end
      end


      # @return [Packet, nil]
      #
      # @raise [ReadError]
      #   This exception is raised if there was an error calling
      #   pcap_next_ex().
      #
      # @raise [TimeoutError]
      #   This exception is raised if the timeout expires
      #
      def next
        hdr_p = MemoryPointer.new(:pointer)
        buf_p = MemoryPointer.new(:pointer)

        case PCap.pcap_next_ex(_pcap, hdr_p, buf_p)
        when -1 # error
          raise(ReadError, geterr(), caller)
        when 0  # live capture read timeout expired
          return nil
        when -2 # savefile packets exhausted
          return nil
        when 1
          hdr = PacketHeader.new( hdr_p.get_pointer(0) )
          return Packet.new(hdr, buf_p.get_pointer(0))
        end
      end

      alias next_extra next
      alias next_ex next


      # Sets a flag that will force dispatch() or loop() to return rather 
      # than looping; they will return the number of packets that have been 
      # processed so far, or nil if no packets have been processed so far.
      #
      # breakloop does not guarantee that no further packets will be
      # processed by dispatch() or loop() after it is called. At most
      # one more packet may be processed.
      #
      def breakloop
        PCap.pcap_breakloop(_pcap)
      end

      alias stop breakloop

      private
        def _wrap_callback(&block)
          lambda {|u, h, b| block.call(self, Packet.new(h, b), u) }
        end

    end # CommonWrapper

    # A wrapper class for pcap devices opened with open_offline()
    class FileWrapper < CaptureWrapper
      attr_accessor :path

      def initialize(pcap, opts={}, &block)
        @path = opts[:path]
        super(pcap, opts, &block)
      end

      def swapped?
        PCap.pcap_is_swapped(_pcap) == 1 ? true : false
      end
    end


    # A wrapper class for pcap devices opened with open_live()
    class LiveWrapper < CaptureWrapper
      attr_reader :device, :promisc, :timeout, :direction

      def initialize(pcap, opts={}, &block)
        unless @device=(opts[:device] || opts[:dev])
          raise(ArgumentError, "A device name must be specified with :device")
        end

        @promisc   = opts[:promisc]
        @timeout   = opts[:timeout]
        @direction = (opts[:direction] || opts[:dir])

        # call super to get all our ducks in a row
        super(pcap, opts={}, &block)

        set_direction(@direction) if @direction

        # Cache network and netmask from pcap_lookupdev
        # These pointers may be used internally (and should get autoreleased)
        @netp, @maskp = nil
        begin
          PCap.lookupnet(@device) do |netp, maskp|
            @netp = netp
            @maskp = maskp
          end
        rescue LibError
          warn "Warning: #{$!}"
        end

      end

      # Returns the dotted notation string for the IPv4 network address for 
      # the device used by this pcap interface.
      def network
        return nil unless @netp
        @network ||= @netp.get_array_of_uchar(0,4).join('.')
      end

      # Returns the dotted notation string for the IPv4 netmask for the device
      # used by this pcap interface.
      def netmask
        return nil unless @maskp
        @netmask ||= @maskp.get_array_of_uchar(0,4).join('.')
      end

      # Returns the 32-bit numeric representation of the IPv4 network address
      # for this device.
      def network_n32
        return nil unless @netp
        PCap.ntohl(@netp.get_uint32(0))
      end

      # Returns the 32-bit numeric representation of the IPv4 network address
      # for this device.
      def netmask_n32
        return nil unless @maskp
        PCap.ntohl(@maskp.get_uint32(0))
      end

      # Sets the direction for which packets will be captured.
      #
      def set_direction(dir)
        dirs = PCap.enum_type(:pcap_direction_t)
        if PCap.pcap_setdirection(_pcap, dirs[:"pcap_d_#{dir}"]) == 0
          return true
        else
          raise(LibError, "pcap_setdirection(): #{geterr()}", caller)
        end
      end

      alias direction= set_direction

      # set the state of non-blocking mode on a capture device
      #
      # @param [Boolean] mode
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error message 
      #   from libpcap.
      #
      def set_non_blocking(mode)
        mode =  mode ? 1 : 0
        if PCap.pcap_setnonblock(_pcap, mode, @errbuf) == 0
          return mode == 1
        else
          raise(LibError, "pcap_setnonblock(): #{@errbuf.to_s}", caller)
        end
      end

      alias non_blocking= set_non_blocking

      # get the state of non-blocking mode on a capture device
      #
      # @return [Boolean]
      #   non-blocking mode
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error message 
      #   from libpcap.
      #
      def non_blocking
        if (mode=PCap.pcap_getnonblock(_pcap, @errbuf)) == -1
          raise(LibError, "pcap_getnonblock(): #{@errbuf.to_s}", caller)
        else
          return mode == 1
        end
      end

      alias non_blocking? non_blocking

      # get capture statistics
      #
      # @return [Stats]
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error message 
      #   from libpcap.
      #
      def stats
        stats = Stat.new
        unless PCap.pcap_stats(_pcap, stats) == 0
          raise(LibError, "pcap_stats(): #{geterr()}")
        end
        return stats
      end
    end

    attach_function :ntohl, [:uint32], :uint32
    attach_function :free, [:pointer], :void

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
    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, BPFProgram, :string, :int, :bpf_uint32], :int

    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pcap_t, :pointer], :int

    attach_function :pcap_set_datalink, [:pcap_t, :int], :int
    attach_function :pcap_snapshot, [:pcap_t], :int
    attach_function :pcap_is_swapped, [:pcap_t], :int
    attach_function :pcap_dump_open, [:pcap_t, :string], :pcap_dumper_t

    attach_function :pcap_major_version, [:pcap_t], :int
    attach_function :pcap_minor_version, [:pcap_t], :int

    #### XXX not sure if we even want FILE io stuff yet (or ever).

    #attach_function :pcap_fopen_offline, [:FILE, :pointer], :pcap_t
    #attach_function :pcap_file, [:pcap_t], :FILE
    #attach_function :pcap_dump_fopen, [:pcap_t, :FILE], :pcap_dumper_t
    #attach_function :pcap_fileno, [:pcap_t], :int

  end
end
