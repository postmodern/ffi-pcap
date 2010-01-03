require 'pcap-ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    extend FFI::Library

    ffi_lib 'libpcap'

    typedef :int, :bpf_int32
    typedef :uint, :bpf_uint32
    typedef :ushort, :sa_family_t

    typedef :pointer, :pcap_t
    typedef :pointer, :pcap_dumper_t
    typedef :pointer, :pcap_if_t
    typedef :pointer, :pcap_addr_t

    enum :pcap_direction_t, [
      :pcap_d_inout,
      :pcap_d_in,
      :pcap_d_out
    ]

    callback :pcap_handler, [:pointer, :pointer, :pointer], :void

    attach_function :pcap_lookupdev, [:pointer], :string
    attach_function :pcap_lookupnet, [:string, :pointer, :pointer, :pointer], :int
    attach_function :pcap_open_live, [:string, :int, :int, :int, :pointer], :pcap_t
    attach_function :pcap_open_dead, [:int, :int], :pcap_t
    attach_function :pcap_open_offline, [:string, :pointer], :pcap_t
    attach_function :pcap_fopen_offline, [:pointer, :string], :pcap_t
    attach_function :pcap_close, [:pcap_t], :void
    attach_function :pcap_loop, [:pcap_t, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_dispatch, [:pcap_t, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_next, [:pcap_t, :pointer], :pointer
    attach_function :pcap_next_ex, [:pcap_t, :pointer, :pointer], :int
    attach_function :pcap_breakloop, [:pcap_t], :void
    attach_function :pcap_stats, [:pcap_t, :pointer], :int
    attach_function :pcap_setfilter, [:pcap_t, :pointer], :int
    attach_function :pcap_setdirection, [:pcap_t, :pcap_direction_t], :int
    attach_function :pcap_getnonblock, [:pcap_t, :pointer], :int
    attach_function :pcap_setnonblock, [:pcap_t, :int, :pointer], :int
    attach_function :pcap_perror, [:pcap_t, :string], :void
    attach_function :pcap_inject, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pcap_t, :pointer, :int], :int
    attach_function :pcap_strerror, [:int], :string
    attach_function :pcap_geterr, [:pcap_t], :string
    attach_function :pcap_compile, [:pcap_t, :pointer, :string, :int, :bpf_uint32], :int
    attach_function :pcap_compile_nopcap, [:int, :int, :pointer, :string, :int, :bpf_uint32], :int
    attach_function :pcap_freecode, [:pointer], :void
    attach_function :pcap_datalink, [:pcap_t], :int
    attach_function :pcap_list_datalinks, [:pointer, :pointer], :int
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
    attach_function :pcap_dump, [:pointer, :pointer, :pointer], :void

    attach_function :pcap_findalldevs, [:pointer, :pointer], :int
    attach_function :pcap_freealldevs, [:pcap_if_t], :void

    attach_function :pcap_lib_version, [], :string

    attach_function :bpf_filter, [:pointer, :pointer, :uint, :uint], :uint
    attach_function :bpf_validate, [:pointer, :int], :int
    attach_function :bpf_image, [:pointer, :int], :string
    attach_function :bpf_dump, [:pointer, :int], :void


    # lazily bind the UNIX/WIN32/MSDOS #ifdefs

    # Unix Only:
    begin
      attach_function :pcap_get_selectable_fd, [:pcap_t], :int
    rescue FFI::NotFoundError
      $pcap_not_unix=true
    end

    # Win32 only:
    begin
      attach_function :pcap_setbuff, [:pcap_t, :int], :int
      attach_function :pcap_setmode, [:pcap_t, :int], :int
      attach_function :pcap_setmintocopy, [:pcap_t, :int], :int
      MODE_CAPT = 0
      MODE_STAT = 1
      MODE_MON  = 2
    rescue FFI::NotFoundError
      $pcap_not_win32=true
    end if $pcap_not_unix

    # MSDOS only???:
    begin
      attach_function :pcap_stats_ex, [:pcap_t, :pointer], :int
      attach_function :pcap_set_wait, [:pcap_t, :pointer, :int], :void
      attach_function :pcap_mac_packets, [], :ulong
    rescue FFI::NotFoundError
    end if $pcap_not_win32

  end
end
