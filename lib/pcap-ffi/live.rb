require 'pcap-ffi/capture_wrapper'

module FFI
  module PCap

    # Creates a pcap interface for capturing from the network.
    #
    # @param [Hash] opts
    #   Options are ignored and passed to CaptureWrapper.new except those below.
    #
    # @option opts [optional, String, nil] :device, :dev
    #   The device to open. On some platforms, this can be "any". If nil or 
    #   unspecified PCap.lookupdev() is called to obtain a default device. 
    #
    # @option opts [optional, Integer] :snaplen
    #   The snapshot length for the pcap object. Defaults to DEFAULT_SNAPLEN
    #
    # @option opts [optional, Boolean] :promisc
    #   Specifies if the interface is to be put into promiscuous mode. Defaults
    #   to false.
    #
    # @option opts [optional, Integer] :timeout
    #   Specifies the read timeout in milliseconds. Defaults to DEFAULT_TO_MS
    #
    # @return [Live]
    #   A FFI::PCap::Live wrapper.
    #
    # @raise [LibError]
    #   On failure, an exception is raised with the relevant error 
    #   message from libpcap.
    #
    # @raise [ArgumentError]
    #   May raise an exception if a :device cannot be autodetected using 
    #   PCap.lookupdev() for any reason. This should never happen on most platforms.
    #
    class Live < CaptureWrapper
      DEFAULT_TO_MS = 1000     # Default timeout for pcap_open_live()

      attr_reader :device, :promisc, :timeout, :direction

      def initialize(opts=nil)
        opts ||= {}
        @device = opts[:device] || opts[:dev] || PCap.lookupdev()
        unless @device
          raise(ArgumentError, "Couldn't detect a device. One must be specified.")
        end

        @snaplen   = opts[:snaplen] || DEFAULT_SNAPLEN
        @promisc   = opts[:promisc] ? 1 : 0
        @timeout   = opts[:timeout] || DEFAULT_TO_MS
        @direction = (opts[:direction] || opts[:dir])

        @errbuf = ErrorBuffer.create()
        @pcap = PCap.pcap_open_live(@device, @snaplen, @promisc, @timeout, @errbuf)
        raise(LibError, "pcap_open_live(): #{errbuf.to_s}") if @pcap.null?

        # call super to get all our ducks in a row
        super(@pcap, opts)

        set_direction(@direction) if @direction

        # Cache network and netmask from pcap_lookupdev.
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

        if block_given?
          yield self
          self.close()
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

      # Get capture statistics
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

      # Transmit a packet (not supported on all platforms)
      #
      # @param [Packet, String] obj
      #   The packet to send. This can be a Packet or String object.
      #
      # @raise [ArgumentError]
      #   An exception is raised if the pkt object type is incorrect or
      #   if it is a Packet and the body pointer is null. 
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant libpcap
      #   error message.
      #
      def inject(pkt)
        if pkt.kind_of? Packet
          len = pkt.caplen
          bufp = pkt.body_ptr
          raise(ArgumentError, "packet data null pointer") if bufp.null?
        elsif pkt.kind_of? String
          len = pkt.size
          bufp = FFI::MemoryPointer.from_string(pkt)
        else
          raise(ArgumentError, "Don't know how to inject #{pkt.class}")
        end

        if (sent=PCap.pcap_inject(_pcap, bufp, len)) < 0
          raise(LibError, "pcap_inject(): #{geterr()}")
        end
        return sent
      end

      alias sendpacket inject
      alias send_packet inject
    end

    attach_function :ntohl, [:uint32], :uint32

    attach_function :pcap_open_live, [:string, :int, :int, :int, :pointer], :pcap_t
    attach_function :pcap_setdirection, [:pcap_t, :pcap_direction_t], :int
    attach_function :pcap_getnonblock, [:pcap_t, :pointer], :int
    attach_function :pcap_setnonblock, [:pcap_t, :int, :pointer], :int
    attach_function :pcap_stats, [:pcap_t, Stat], :int
    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
  end
end
