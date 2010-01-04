module FFI
  module PCap
    typedef :int,  :bpf_int32
    typedef :uint, :bpf_uint32

    enum :pcap_direction_t, [
      :pcap_d_inout,
      :pcap_d_in,
      :pcap_d_out
    ]
 
    typedef :pointer, :pcap_t
    typedef :pointer, :pcap_dumper_t
    typedef :pointer, :pcap_addr_t
  end
end
