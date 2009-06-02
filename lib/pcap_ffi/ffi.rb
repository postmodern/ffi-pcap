require 'pcap_ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    extend FFI::Library

    ffi_lib 'libpcap'

    enum :pcap_direction, [
      :pcap_d_inout,
      :pcap_d_in,
      :pcap_d_out
    ]

    callback :pcap_handler, [:pointer, :pointer, :pointer], :void

    attach_function :pcap_lookupdev, [:pointer], :string
    attach_function :pcap_lookupnet, [:string, :pointer, :pointer, :pointer], :int
    attach_function :pcap_open_live, [:string, :int, :int, :int, :pointer], :pointer
    attach_function :pcap_open_dead, [:int, :int], :pointer
    attach_function :pcap_open_offline, [:string, :pointer], :pointer
    attach_function :pcap_fopen_offline, [:pointer, :string], :pointer
    attach_function :pcap_close, [:pointer], :void
    attach_function :pcap_loop, [:pointer, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_dispatch, [:pointer, :int, :pcap_handler, :pointer], :int
    attach_function :pcap_next, [:pointer, :pointer], :pointer
    attach_function :pcap_next_ex, [:pointer, :pointer, :pointer], :int
    attach_function :pcap_breakloop, [:pointer], :void
    attach_function :pcap_stats, [:pointer, :pointer], :int
    attach_function :pcap_setfilter, [:pointer, :pointer], :int
    attach_function :pcap_setdirection, [:pointer, :pcap_direction], :int
    attach_function :pcap_getnonblock, [:pointer, :pointer], :int
    attach_function :pcap_setnonblock, [:pointer, :int, :pointer], :int
    attach_function :pcap_perror, [:pointer, :string], :void
    attach_function :pcap_inject, [:pointer, :pointer, :int], :int
    attach_function :pcap_sendpacket, [:pointer, :pointer, :int], :int
    attach_function :pcap_strerror, [:int], :string
    attach_function :pcap_geterr, [:pointer], :string
    attach_function :pcap_compile, [:pointer, :pointer, :string, :int, :bpf_uint32], :int
    attach_function :pcap_compile_nopcap, [:int, :int, :pointer, :string, :int, :bpf_uint32], :int
    attach_function :pcap_freecode, [:pointer], :void
    attach_function :pcap_datalink, [:pointer], :int
    attach_function :pcap_list_datalinks, [:pointer, :pointer], :int
    attach_function :pcap_set_datalink, [:pointer, :int], :int
    attach_function :pcap_datalink_name_to_val, [:string], :int
    attach_function :pcap_datalink_val_to_name, [:int], :string
    attach_function :pcap_datalink_val_to_description, [:int], :string
    attach_function :pcap_snapshot, [:pointer], :int
    attach_function :pcap_is_swapped, [:pointer], :int
    attach_function :pcap_major_version, [:pointer], :int
    attach_function :pcap_minor_version, [:pointer], :int

    attach_function :pcap_file, [:pointer], :pointer
    attach_function :pcap_fileno, [:pointer], :int

    attach_function :pcap_dump_open, [:pointer, :string], :pointer
    attach_function :pcap_dump_fopen, [:pointer, :pointer], :pointer
    attach_function :pcap_dump_file, [:pointer], :pointer
    attach_function :pcap_dump_ftell, [:pointer], :long
    attach_function :pcap_dump_flush, [:pointer], :int
    attach_function :pcap_dump_close, [:pointer], :void
    attach_function :pcap_dump, [:pointer, :pointer, :pointer], :void

    attach_function :pcap_findalldevs, [:pointer, :pointer], :int
    attach_function :pcap_freealldevs, [:pointer], :void

    attach_function :pcap_lib_version, [], :string

    attach_function :bpf_filter, [:pointer, :pointer, :uint, :uint], :uint
    attach_function :bpf_validate, [:pointer, :int], :int
    attach_function :bpf_image, [:pointer, :int], :string
    attach_function :bpf_dump, [:pointer, :int], :void

    # TODO: WIN32/MSDOS/UN*X specific definitions
  end
end
