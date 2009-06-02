require 'pcap_ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    class InAddr < FFI::Struct

      layout :s_addr, :in_addr_t

    end
  end
end
