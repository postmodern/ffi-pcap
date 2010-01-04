
module FFI
  module PCap

    # Get the version information for libpcap.
    #
    # @raise [StandardError]
    #   This exception may indicate you need higher privileges.
    #
    # @return [String]
    #  Information about the version of the libpcap library being used; 
    #  note that it  contains more information than just a version number.
    #   
    def PCap.lib_version
      PCap.pcap_lib_version
    end


    # Finds the default device on which to capture. 
    #
    # @return [String]
    #   The device name.
    #
    # @raise [StandardError]
    #   This exception may indicate you need higher privileges.
    #
    def PCap.device
      errbuf = ErrorBuffer.new

      unless (name = PCap.pcap_lookupdev(errbuf))
        raise(StandardError, errbuf.to_s, caller)
      end

      return name
    end

    # Get a list of all capture devices.
    #
    # @yield [dev]
    #
    # @yieldparam [Interface] dev
    #   An Interface structure for the device.
    #
    # @return [nil]
    #
    # @raise [StandardError]
    #   This exception may indicate you need higher privileges.
    #
    def PCap.each_device
      devices = ::FFI::MemoryPointer.new(:pointer)
      errbuf = ErrorBuffer.new

      PCap.pcap_findalldevs(devices, errbuf)
      node = devices.get_pointer(0)

      if node.null?
        raise(StandardError, errbuf.to_s, caller)
      end

      device = Interface.new(node)

      while device
        yield(device)
        device = device.next
      end

      PCap.pcap_freealldevs(node)
      return nil
    end


    # Opens a device for capturing from the network.
    #
    # @option options [String, nil] :device
    #   The device to capture from. A device of "any" or nil can be used
    #   to capture packets from all interfaces.
    #
    # @param [Hash] options
    #   Options are ignored and passed to Handler.new except those below.
    #
    # @option options [Integer] :snaplen
    #   The snapshot length for the pcap object. Defaults to SNAPLEN
    #
    # @option options [Boolean] :promisc
    #   Specifies if the interface is to be put into promiscuous mode.
    #
    # @option options [Integer] :timeout
    #   Specifies the read timeout in milliseconds.
    #
    # @return [Handler]
    #   A FFI::PCap::Handler
    #
    def PCap.open_live(options={},&block)
      device = options[:device]
      errbuf = ErrorBuffer.new

      unless device
        unless (device = PCap.pcap_lookupdev(errbuf))
          raise(RuntimeError, errbuf.to_s, caller)
        end
      end

      promisc = (options[:promisc])? 1 : 0
      snaplen = (options[:snaplen] || Handler::SNAPLEN)
      to_ms = (options[:timeout] || 0)

      ptr = PCap.pcap_open_live(device, snaplen, promisc, to_ms, errbuf)

      if ptr.null?
        raise(StandardError, errbuf.to_s, caller)
      end

      return Handler.new(ptr, options, &block)
    end


    # Creates a fake pcap interface for compiling filters or opening a
    # capture for output.
    #
    # @param [String] datalink
    #   The link-layer type for pcap.
    #
    # @param [Hash] options
    #   Options are ignored and passed to Handler.new except those below.
    #
    # @option options [Integer] :snaplen
    #   The snapshot length for the pcap object. Defaults to SNAPLEN
    #
    # @return [Handler]
    #   A FFI::PCap::Handler
    #
    def PCap.open_dead(datalink, options={})
      datalink = DataLink[datalink]
      snaplen = (options[:snaplen] || Handler::SNAPLEN)

      return Handler.new(PCap.pcap_open_dead(datalink, snaplen), options)
    end


    # Opens a saved capture file for reading.
    # 
    # @param [String] path
    #   Path to the file to open.
    #
    # @param [Hash] options
    #   Options are ignored and passed to Handler.new
    #
    # @return [Handler]
    #   A FFI::PCap::Handler
    #
    def PCap.open_offline(path, options={})
      path = File.expand_path(path)
      errbuf = ErrorBuffer.new

      ptr = PCap.pcap_open_offline(path, errbuf)

      if ptr.null?
        raise(StandardError, errbuf.to_s, caller)
      end

      return Handler.new(ptr, options)
    end
  end
end
