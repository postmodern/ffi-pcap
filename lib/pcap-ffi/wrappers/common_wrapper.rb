module FFI
  module PCap

    # An abstract base wrapper class with features common to all pcap
    # wrapper types. Do not use this directly. Instead refer to LiveWrapper, 
    # DeadWrapper, or FileWrapper class for open_live, open_dead, or open_file 
    # respectively.
    class CommonWrapper

      attr_accessor :pcap

      def initialize(pcap, opts={})
        @pcap = pcap
        @closed = false
        @errbuf = ErrorBuffer.create

        trap('INT') {|s| stop(); close(); raise(SignalException, s)}
        trap('TERM') {|s| stop(); close(); raise(SignalException, s)}

        if block_given?
          yield(self)
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
        raise(LibError, "pcap_dump_open(): #{geterr()}") if dp.null?
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

    attach_function :free, [:pointer], :void

    attach_function :pcap_close, [:pcap_t], :void
    attach_function :pcap_setfilter, [:pcap_t, BPFProgram], :int
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pcap_t, :pointer], :int
    attach_function :pcap_set_datalink, [:pcap_t, :int], :int
    attach_function :pcap_snapshot, [:pcap_t], :int
    attach_function :pcap_dump_open, [:pcap_t, :string], :pcap_dumper_t

  end
end
