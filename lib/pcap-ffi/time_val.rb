module FFI
  module PCap
    class TimeVal < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :tv_sec, :time_t
        field :tv_usec, :suseconds_t
      end

      alias sec tv_sec
      alias usec tv_usec

      def to_time
        Time.at(self[:tv_sec], self[:tv_usec])
      end

#      def to_s
#        to_time.to_s
#      end

    end
  end
end
