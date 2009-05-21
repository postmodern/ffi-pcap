require 'pcap/typedefs'

require 'ffi/struct'

module FFI
  module PCap
    class TimeVal < FFI::Struct
      layout :tv_sec, :time_t,
             :tv_usec, :suseconds_t

      def sec
        self[:tv_sec]
      end

      def usec
        self[:tv_usec]
      end

    end
  end
end
