
module FFI
  module PCap
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

    attach_function :pcap_setdirection, [:pcap_t, :pcap_direction_t], :int
    attach_function :pcap_getnonblock, [:pcap_t, :pointer], :int
    attach_function :pcap_setnonblock, [:pcap_t, :int, :pointer], :int
    attach_function :pcap_stats, [:pcap_t, Stat], :int

    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
  end
end
