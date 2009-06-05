require 'pcap_ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    class InAddr < FFI::Struct

      layout :s_addr, [NativeType::UINT8, 4]

    end
  end
end
