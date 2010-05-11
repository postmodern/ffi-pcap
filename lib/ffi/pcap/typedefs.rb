module FFI
module PCap
  typedef :pointer, :FILE

  typedef :int,  :bpf_int32
  typedef :uint, :bpf_uint32

  enum :pcap_direction_t, [
    :pcap_d_inout,
    :pcap_d_in,
    :pcap_d_out
  ]

  # For Win32-only pcap_setmode()
  enum :pcap_w32_modes_enum, [ :capt, :stat, :mon ] 

  typedef :pointer, :pcap_t
  typedef :pointer, :pcap_dumper_t
  typedef :pointer, :pcap_addr_t

  # add some of the more temperamental FFI types if needed
  [ [:long, :time_t],
    [:uint32, :suseconds_t],
  ].each {|t, d| begin; find_type(d); rescue TypeError; typedef t,d; end }

end
end
