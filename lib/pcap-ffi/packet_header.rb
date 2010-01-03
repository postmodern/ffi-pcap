require 'pcap-ffi/time_val'

module FFI
  module PCap
    class PacketHeader < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        struct :ts,      TimeVal
        field  :caplen,  :bpf_uint32
        field  :len,     :bpf_uint32
      end

      alias timestamp ts
      alias captured caplen
      alias length len

    end
  end
end
