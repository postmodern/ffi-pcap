require 'pcap/typedefs'
require 'pcap/timeval'

require 'ffi/struct'

module FFI
  module PCap
    class PacketHeader < FFI::Struct
      layout :ts, TimeVal
             :caplen, :bpf_uint32,
             :len, :bpf_uint32
    end
  end
end
