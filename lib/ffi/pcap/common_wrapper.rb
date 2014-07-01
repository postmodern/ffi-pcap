module FFI
  module PCap
    #
    # An abstract base wrapper class with features common to all pcap
    # wrapper types. Do not use this directly. Instead refer to {Live}, 
    # {Dead}, or {Offline} class for {PCap.open_live}, {PCap.open_dead}, or
    # {PCap.open_file}, respectively.
    #
    class CommonWrapper

      attr_accessor :pcap

      def initialize(pcap, opts={})
        @pcap     = pcap
        @closed   = false
        @errbuf ||= ErrorBuffer.new

        yield self if block_given?
      end

      #
      # Returns the DataLink for the pcap device.
      #
      def datalink
        @datalink ||= DataLink.new(PCap.pcap_datalink(_pcap))
      end

      #
      # Returns an array of supported DataLinks for the pcap device.
      #
      def supported_datalinks
        dlt_lst = MemoryPointer.new(:pointer)

        if (cnt = PCap.pcap_list_datalinks(_pcap, dlt_lst)) < 0
          raise(LibError, "pcap_list_datalinks(): #{geterr}",caller)
        end

        # extract datalink values 
        p = dlt_lst.get_pointer(0)
        ret = p.get_array_of_int(0, cnt).map {|dlt| DataLink.new(dlt) }

        CRT.free(p)
        return ret
      end

      #
      # Indicates whether the pcap interface is already closed.
      #
      def closed?
        @closed == true
      end

      def ready?
        (@closed == false && !(@pcap.nil?) && !(@pcap.null?))
      end

      #
      # Closes the pcap interface using libpcap.
      #
      def close
        unless @closed
          PCap.pcap_close(_pcap)

          @closed = true
          @pcap = nil
        end
      end

      #
      # Returns the pcap interface pointer.
      #
      # @return [FFI::Pointer]
      #   Internal pointer to a pcap_t handle.
      #
      def to_ptr
        _check_pcap()
      end

      #
      # Gets the snapshot length.
      #
      # @return [Integer]
      #  Snapshot length for the pcap interface.
      def snaplen
        PCap.pcap_snapshot(_pcap)
      end

      #
      # Compiles a pcap filter but does not apply it to the pcap interface.
      #
      # @param [String] expression
      #   A pcap filter expression. See `pcap-filter(7)` manpage for syntax.
      #
      # @param [Hash] opts
      #   Additional options for compile
      #
      # @option opts [optional, Integer] :optimize
      #   Optimization flag. 0 means don't optimize. Defaults to 1.
      #
      # @option opts [optional, Integer] :netmask
      #   A 32-bit number representing the IPv4 netmask of the network on
      #   which packets are being captured. It is only used when checking
      #   for IPv4 broadcast addresses in the filter program.
      #   Default: 0 (unspecified netmask)
      #
      # @return [BPF::Program]
      #   A BPF program structure for the compiled filter.
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error
      #   message from libpcap.
      #
      def compile(expression, opts={})
        optimize = opts[:optimize] || 1
        netmask  = opts[:netmask] || 0 
        code = BPFProgram.new

        if PCap.pcap_compile(_pcap, code, expression, optimize, netmask) != 0
          raise(LibError,"pcap_compile(): #{geterr()}",caller)
        end

        return code
      end

      #
      # @return [Dumper]
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error
      #   message from libpcap.
      #
      def open_dump(path)
        dp = PCap.pcap_dump_open(_pcap, File.expand_path(path))

        if dp.null?
          raise(LibError,"pcap_dump_open(): #{geterr}",caller)
        end

        return Dumper.new(dp)
      end

      #
      # @return [String]
      #   The error text pertaining to the last pcap library error.
      #
      def geterr
        PCap.pcap_geterr(_pcap)
      end

      alias error geterr

      private

      #
      # Raises an exception if `@pcap` is not set.
      #
      # Internal sanity check to confirm the pcap instance
      # variable has been set. Otherwise very bad things can 
      # ensue by passing a null pointer to various libpcap 
      # functions.
      #
      def _check_pcap
        if @pcap.nil?
          raise(NoDeviceError,"nil pcap device",caller)
        else
          @pcap
        end
      end

      #
      # Raises an exception if @pcap is not set or is a null pointer.
      #
      # Internal sanity check to confirm the pcap pointer
      # variable has been set and is not a null pointer. 
      # Otherwise very bad things can ensue by passing a null 
      # pointer to various libpcap functions.
      #
      def _pcap
        ptr = _check_pcap

        if ptr.null?
          raise(NullPointerError,"null pointer to pcap device",caller)
        else
          ptr
        end
      end

    end

    attach_function :pcap_close, [:pcap_t], :void
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pcap_t, :pointer], :int
    attach_function :pcap_set_datalink, [:pcap_t, :int], :int
    attach_function :pcap_snapshot, [:pcap_t], :int
    attach_function :pcap_dump_open, [:pcap_t, :string], :pcap_dumper_t

  end
end
