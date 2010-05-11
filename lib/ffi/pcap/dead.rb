require 'ffi/pcap/common_wrapper'

module FFI
  module PCap
    #
    # A wrapper class for pcap devices opened with open_dead()
    #
    class Dead < CommonWrapper

      attr_reader :datalink

      #
      # Creates a fake pcap interface for compiling filters or opening a
      # capture for output.
      #
      # @param [Hash] opts
      #   Options are ignored and passed to the super-class except those
      #   below.
      #
      # @option opts [optional, String, Symbol, Integer] :datalink
      #   The link-layer type for pcap. nil is equivalent to 0
      #   (aka DLT_NULL).
      #
      # @option opts [optional, Integer] :snaplen
      #   The snapshot length for the pcap object.
      #   Defaults to FFI::PCap::DEFAULT_SNAPLEN
      #
      # @return [Dead]
      #   A FFI::PCap::Dead wrapper.
      #
      def initialize(opts={}, &block)
        dl = opts[:datalink] || DataLink.new(0)
        @datalink = dl.kind_of?(DataLink) ? dl : DataLink.new(dl)
        @snaplen  = opts[:snaplen] || DEFAULT_SNAPLEN
        @pcap = FFI::PCap.pcap_open_dead(@datalink.value, @snaplen)
        raise(LibError, "pcap_open_dead(): returned a null pointer") if @pcap.null?
        super(@pcap, opts, &block)
      end

    end

    attach_function :pcap_open_dead, [:int, :int], :pcap_t

  end
end
