require 'pcap_ffi/typedefs'

require 'ffi'

module FFI
  module PCap
    class SockAddr < FFI::Struct
      layout :sa_family, :sa_family_t,
             :sa_data, [:char, 14]

      def family
        self[:sa_family]
      end

    end
  end
end
