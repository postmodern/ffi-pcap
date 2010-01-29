require 'pcap-ffi/capture_wrapper'

module FFI
  module PCap
    # A wrapper class for pcap devices opened with open_offline()
    #
    class Offline < CaptureWrapper
      attr_accessor :path

      # Creates a pcap interface for reading saved capture files.
      #
      # @param [String] path
      #   The path to the file to open.
      #
      # @param [Hash] opts
      #   Options are ignored and passed to the super-class except for those 
      #   below.
      #
      # @option opts [ignored] :path
      #   The :path option will be overridden with the value of the path 
      #   argument.  If specified in opts, its value will be ignored.
      #
      # @return [Offline]
      #   A FFI::PCap::Offline wrapper.
      #
      # @raise [LibError]
      #   On failure, an exception is raised with the relevant error 
      #   message from libpcap.
      #
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
