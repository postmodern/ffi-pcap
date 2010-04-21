require 'enumerator'

module Caper
  DEFAULT_SNAPLEN = 65535  # Default snapshot length for packets

  attach_function :pcap_lookupdev, [:pointer], :string

  # Find the default device on which to capture.
  # 
  # @return [String]
  #   Name of default device
  #
  # @raise [LibError]
  #   On failure, an exception is raised with the relevant error 
  #   message from libpcap.
  #
  def Caper.lookupdev
    e = ErrorBuffer.create()
    unless name = Caper.pcap_lookupdev(e)
      raise(LibError, "pcap_lookupdev(): #{e.to_s}")
    end
    return name
  end


  attach_function :pcap_lookupnet, [:string, :pointer, :pointer, :pointer], :int

  # Determine the IPv4 network number and mask relevant with a network 
  # device.
  # 
  # @param [String] device
  #   The name of the device to look up.
  #
  # @yield [netp, maskp]
  #
  # @yieldparam [FFI::MemoryPointer] netp
  #   A pointer to the network return value.
  #
  # @yieldparam [FFI::MemoryPointer] maskp
  #   A pointer to the netmask return value.
  #
  # @return [nil, String] 
  #   The IPv4 network number and mask presented as "n.n.n.n/m.m.m.m".
  #   nil is returned when a block is specified.
  #
  # @raise [LibError]
  #   On failure, an exception is raised with the relevant error message 
  #   from libpcap. 
  #
  def Caper.lookupnet(device)
    netp  = FFI::MemoryPointer.new(find_type(:bpf_uint32))
    maskp = FFI::MemoryPointer.new(find_type(:bpf_uint32))
    errbuf = ErrorBuffer.create()
    unless Caper.pcap_lookupnet(device, netp, maskp, errbuf) == 0
      raise(LibError, "pcap_lookupnet(): #{errbuf.to_s}")
    end
    if block_given?
      yield(netp, maskp)
    else
      return( netp.get_array_of_uchar(0,4).join('.') << "/" <<
              maskp.get_array_of_uchar(0,4).join('.') )
    end
  end
  

  # Opens a new Live device for capturing from the network. See Live.new()
  # for arguments.
  #
  # If passed a block, the block is passed to Live.new() and the Live
  # object is closed after completion of the block
  def Caper.open_live(opts={},&block)
    ret = Live.new(opts, &block)
    return block_given? ? ret.close : ret
  end


  # Opens a new Dead pcap interface for compiling filters or opening
  # a capture for output. See Dead.new() for arguments.
  def Caper.open_dead(opts={}, &block)
    ret = Dead.new(opts, &block)
    return block_given? ? ret.close : ret
  end


  # Opens a saved capture file for reading. See Offline.new for arguments.
  def Caper.open_offline(path, opts={}, &block)
    ret = Offline.new(path, opts={}, &block)
    return block_given? ? ret.close : ret
  end

  # Same as open_offline
  def Caper.open_file(path, opts={}, &block)
    open_offline(path, opts, &block)
  end

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
  # @raise [LibError]
  #   On failure, an exception is raised with the relevant error 
  #   message from libpcap.
  #
  def Caper.each_device
    devices = ::FFI::MemoryPointer.new(:pointer)
    errbuf = ErrorBuffer.create()

    Caper.pcap_findalldevs(devices, errbuf)
    node = devices.get_pointer(0)

    if node.null?
      raise(LibError, "pcap_findalldevs(): #{errbuf.to_s}")
    end

    device = Interface.new(node)

    while device
      yield(device)
      device = device.next
    end

    Caper.pcap_freealldevs(node)
    return nil
  end


  # Returns an array of device name and network/netmask pairs for
  # each interface found on the system.
  #
  # If an interface does not have an address assigned, its network/netmask
  # value is returned as a nil value.
  def Caper.dump_devices
    Caper.enum_for(:each_device).map do |dev| 
      net = begin; Caper.lookupnet(dev.name); rescue LibError; end
      [dev.name, net]
    end
  end


  # Returns an array of device names for each interface found on the system.
  def Caper.device_names
    Caper.enum_for(:each_device).map {|dev| dev.name }
  end

  attach_function :pcap_lib_version, [], :string


  # Get the version information for libpcap.
  #
  # @return [String]
  #  Information about the version of the libpcap library being used; 
  #  note that it  contains more information than just a version number.
  #   
  def Caper.lib_version
    Caper.pcap_lib_version
  end


  # Extract just the version number from the lib_version string.
  #
  # @return [String]
  #  Version number.
  #   
  def Caper.lib_version_number
    if lib_version() =~ /libpcap version (\d+\.\d+.\d+)/
      return $1
    end
  end


  # Unix Only:
  begin

    attach_function :pcap_get_selectable_fd, [:pcap_t], :int


    # Drops privileges back to the uid of the SUDO_USER environment 
    # variable.
    #
    # Only available on Unix.
    #
    # This is useful for the paranoid when sudo is used to run a 
    # ruby pcap program as root.
    #
    # This method can generally be called right after a call to 
    # open_live() has returned a pcap handle or another privileged
    # call has completed. Note, however, that once privileges are 
    # dropped, pcap functions that a require higher privilege will 
    # no longer work.
    #
    # @raise [StandardError]
    #   An error is raised if privileges cannot be dropped for 
    #   some reason. This may be because the SUDO_USER environment 
    #   variable is not set, because we already have a lower
    #   privilige and the SUDO_USER id is not the current uid,
    #   or because the SUDO_USER environment variable is not
    #   a valid user.
    #
    def Caper.drop_sudo_privs
      if ENV["SUDO_USER"] and pwent=Etc.getpwnam(ENV["SUDO_USER"])
        Process::Sys.setgid(pwent.gid) 
        Process::Sys.setegid(pwent.gid) 
        Process::Sys.setuid(pwent.uid)
        Process::Sys.seteuid(pwent.uid)
        return true if ( 
          Process::Sys.getuid  == pwent.uid and 
          Process::Sys.geteuid == pwent.uid and 
          Process::Sys.getgid  == pwent.gid and 
          Process::Sys.getegid == pwent.gid )
      end
      raise(StandardError, "Unable to drop privileges")
    end

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


  #### XXX not sure if we even want FILE io stuff yet (or ever).

  #attach_function :pcap_fopen_offline, [:FILE, :pointer], :pcap_t
  #attach_function :pcap_file, [:pcap_t], :FILE
  #attach_function :pcap_dump_fopen, [:pcap_t, :FILE], :pcap_dumper_t
  #attach_function :pcap_fileno, [:pcap_t], :int
end
