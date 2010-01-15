require 'pcap-ffi/capture_wrapper'

module FFI
  module PCap
    # A wrapper class for pcap devices opened with open_offline()
    # Creates a pcap interface for reading saved capture files.
    #
    class Offline < CaptureWrapper
      attr_accessor :path

      def initialize(path, opts={}, &block)
        @path = path
        @errbuf = ErrorBuffer.create()
        @pcap = PCap.pcap_open_offline(File.expand_path(@path), @errbuf)
        raise(LibError, "pcap_open_offline(): #{@errbuf.to_s}") if @pcap.null?
        super(@pcap, opts, &block)
      end

      def swapped?
        PCap.pcap_is_swapped(_pcap) == 1 ? true : false
      end

      def file_version
        "#{PCap.pcap_major_version(_pcap)}.#{PCap.pcap_minor_version(_pcap)}"
      end
    end

    attach_function :pcap_open_offline, [:string, :pointer], :pcap_t
    attach_function :pcap_is_swapped, [:pcap_t], :int
    attach_function :pcap_major_version, [:pcap_t], :int
    attach_function :pcap_minor_version, [:pcap_t], :int

  end
end
