require 'pcap-ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    class SockAddr < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :sa_family, :sa_family_t
        array :sa_data,   [:char, 14]
      end

      alias family sa_family
    end
  end
end
