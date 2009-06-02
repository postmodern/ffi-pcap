require 'pcap_ffi/typedefs'

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

      def to_time
        Time.at(self[:tv_sec],self[:tv_usec])
      end

      def to_s
        to_time.to_s
      end

    end
  end
end
