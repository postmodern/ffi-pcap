module FFI
  module PCap
    # A wrapper class for pcap devices opened with open_offline()
    class Offline < CaptureWrapper
      attr_accessor :path

      def initialize(pcap, opts={}, &block)
        @path = opts[:path]
        super(pcap, opts, &block)
      end

      def swapped?
        PCap.pcap_is_swapped(_pcap) == 1 ? true : false
      end

      def file_version
        "#{PCap.pcap_major_version(_pcap)}.#{PCap.pcap_minor_version(_pcap)}"
      end
    end

    attach_function :pcap_is_swapped, [:pcap_t], :int
    attach_function :pcap_major_version, [:pcap_t], :int
    attach_function :pcap_minor_version, [:pcap_t], :int

  end
end
