require 'pcap/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class PacketHeader < FFI::Struct
      layout :tv_sec, :time_t, # TODO: nested struct
             :tv_usec, :suseconds_t,
             :caplen, :bpf_uint32,
             :len, :bpf_uint32
    end
  end
end
