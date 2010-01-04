require 'pcap-ffi/time_val'

module FFI
  module PCap

    # Generic per-packet information, as supplied by libpcap
    class PacketHeader < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        struct :ts,      TimeVal,     :desc => 'time stamp'
        field  :caplen,  :bpf_uint32, :desc => 'length of portion present'
        field  :len,     :bpf_uint32, :desc => 'length of packet (off wire)'
      end

      alias timestamp ts
      alias captured caplen
      alias length len

    end

  end
end
