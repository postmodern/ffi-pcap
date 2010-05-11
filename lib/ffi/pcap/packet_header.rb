module FFI
  module PCap
    #
    # Generic per-packet information, as supplied by libpcap. This structure
    # is used to track only the libpcap header and just contains the
    # timestamp and length information used by libpcap.
    #
    # See pcap_pkthdr struct in pcap.h
    #
    class PacketHeader < FFI::Struct

      include FFI::DRY::StructHelper

      dsl_layout do
        struct :ts,      ::FFI::PCap::TimeVal,     :desc => 'time stamp'
        field  :caplen,  :bpf_uint32, :desc => 'length of portion present'
        field  :len,     :bpf_uint32, :desc => 'length of packet (off wire)'
      end

      alias timestamp ts
      alias captured caplen
      alias length len

    end
  end
end
