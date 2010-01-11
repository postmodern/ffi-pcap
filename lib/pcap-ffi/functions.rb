
module FFI
  module PCap

    callback :pcap_handler, [:pointer, PacketHeader, :pointer], :void

    attach_function :pcap_lookupdev, [:pointer], :string

    # Find the default device on which to capture.
    # 
    # @return [String]
    #   Name of default device
    #
    # @raise [StandardErrror]
    #   On failure, an exception is raised with the associated error message 
    #   from libpcap. The raising of this exception may indicate that you 
    #   need higher privileges.
    #
    def self.lookupdev
      e = ErrorBuffer.new
      unless name=pcap_lookupdev(e)
        raise(StandardError, e.to_s)
      end
      return name
    end


    attach_function :pcap_lookupnet, [:string, :pointer, :pointer, :pointer], :int

    # Determine the IPv4 network number and mask associated with a network 
    # device.
    # 
    # @param [String] device
    #   The name of the device to look up.
    #
    # @return [String] 
    #   The IPv4 network number and mask presented as "n.n.n.n/m.m.m.m"
    #
    # @raise [StandardErrror]
    #   On failure, an exception is raised with the associated error message 
    #   from libpcap. 
    #
    def self.lookupnet(device)
      netp  = FFI::MemoryPointer.new(find_type(:bpf_uint32))
      maskp = FFI::MemoryPointer.new(find_type(:bpf_uint32))
      errbuf = ErrorBuffer.new
      unless pcap_lookupnet(device, netp, maskp, errbuf) == 0
        raise(StandardError, errbuf.to_s)
      end
      return netp.get_array_of_uchar(0,4).join('.') + "/" + 
             maskp.get_array_of_uchar(0,4).join('.')
    end

    attach_function :pcap_open_live, [:string, :int, :int, :int, :pointer], :pcap_t
    
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
          raise(StandardError, errbuf.to_s, caller)
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


    attach_function :pcap_open_dead, [:int, :int], :pcap_t

    # Creates a fake pcap interface for compiling filters or opening a
    # capture for output.
    #
    # @param [String, Symbol, Integer] datalink
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
      dl = datalink.kind_of?(Integer) ? dl : DataLink.name_to_value(datalink.to_s)
      snaplen = (options[:snaplen] || Handler::SNAPLEN)

      return Handler.new(PCap.pcap_open_dead(dl, snaplen), options)
    end


    attach_function :pcap_open_offline, [:string, :pointer], :pcap_t

    # Opens a saved capture file for reading.
    # 
    # @param [String] path
    #   The path to the file to open.
    #
    # @param [Hash] options
    #   Options are ignored and passed to Handler.new
    #
    # @return [Handler]
    #   A FFI::PCap::Handler
    #
    # @raise [StandardErrror]
    #   On failure, an exception is raised with the associated error message 
    #   from libpcap.
    #
    def PCap.open_offline(path, options={})
      errbuf = ErrorBuffer.new
      ptr = PCap.pcap_open_offline(File.expand_path(path), errbuf)

      if ptr.null?
        raise(StandardError, errbuf.to_s, caller)
      end

      return Handler.new(ptr, options)
    end


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
    attach_function :pcap_perror, [:pcap_t, :string], :void
    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_strerror, [:int], :string
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_compile_nopcap, [:int, :int, BPFProgram, :string, :int, :bpf_uint32], :int
    attach_function :pcap_freecode, [BPFProgram], :void
    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pcap_t, :pointer], :int
    attach_function :pcap_set_datalink, [:pcap_t, :int], :int
    attach_function :pcap_datalink_name_to_val, [:string], :int
    attach_function :pcap_datalink_val_to_name, [:int], :string
    attach_function :pcap_datalink_val_to_description, [:int], :string
    attach_function :pcap_snapshot, [:pcap_t], :int
    attach_function :pcap_is_swapped, [:pcap_t], :int


    attach_function :pcap_major_version, [:pcap_t], :int
    attach_function :pcap_minor_version, [:pcap_t], :int


    attach_function :pcap_file, [:pcap_t], :pointer
    attach_function :pcap_fileno, [:pcap_t], :int

    attach_function :pcap_dump_open, [:pcap_t, :string], :pcap_dumper_t
    attach_function :pcap_dump_fopen, [:pcap_t, :pointer], :pcap_dumper_t
    attach_function :pcap_dump_file, [:pcap_dumper_t], :pointer
    attach_function :pcap_dump_ftell, [:pcap_dumper_t], :long
    attach_function :pcap_dump_flush, [:pcap_dumper_t], :int
    attach_function :pcap_dump_close, [:pcap_dumper_t], :void
    attach_function :pcap_dump, [:pointer, PacketHeader, :pointer], :void

    attach_function :pcap_findalldevs, [:pointer, :pointer], :int
    attach_function :pcap_freealldevs, [Interface], :void

    # List all capture devices and yield them each to a block
    #
    # @yield [dev]
    #
    # @yieldparam [Interface] dev
    #   An Interface structure for each device.
    #
    # @return [nil]
    #
    # @raise [StandardErrror]
    #   On failure, an exception is raised with the associated error message 
    #   from libpcap. The raising of this exception may indicate you need 
    #   higher privileges.
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


    attach_function :pcap_lib_version, [], :string

    # Get the version information for libpcap.
    #
    # @return [String]
    #  Information about the version of the libpcap library being used; 
    #  note that it  contains more information than just a version number.
    #   
    def PCap.lib_version
      PCap.pcap_lib_version
    end



    attach_function :bpf_filter, [BPFInstruction, :pointer, :uint, :uint], :uint
    attach_function :bpf_validate, [BPFInstruction, :int], :int
    attach_function :bpf_image, [BPFInstruction, :int], :string
    attach_function :bpf_dump, [BPFProgram, :int], :void


    # Unix Only:
    begin
      attach_function :pcap_get_selectable_fd, [:pcap_t], :int
    rescue FFI::NotFoundError
      $pcap_not_unix=true
    end

    # Win32 only:
    begin
      attach_function :pcap_setbuff, [:pcap_t, :int], :int
      attach_function :pcap_setmode, [:pcap_t, :pcap_w32_modes_enum], :int
      attach_function :pcap_setmintocopy, [:pcap_t, :int], :int
    rescue FFI::NotFoundError
      $pcap_not_win32=true
    end if $pcap_not_unix

    # MSDOS only???:
    begin
      attach_function :pcap_stats_ex, [:pcap_t, StatEx], :int
      attach_function :pcap_set_wait, [:pcap_t, :pointer, :int], :void
      attach_function :pcap_mac_packets, [], :ulong
    rescue FFI::NotFoundError
    end if $pcap_not_win32

  end
end

