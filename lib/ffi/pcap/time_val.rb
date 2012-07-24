module FFI
  module PCap
    class TimeVal < FFI::Struct

      include FFI::DRY::StructHelper

      dsl_layout do
        field :tv_sec, :time_t
        field :tv_usec, :suseconds_t
      end

      #
      # Initializes the new {TimeVal}.
      #
      # @param [Time, FFI::Pointer] timeval
      #   A Time object or a pointer to another {TimeVal}.
      #
      def initialize(timeval=nil)
        case timeval
        when Time
          super()

          self.time = timeval
        else Pointer then super(timeval)
        else         then super()
        end
      end

      alias sec tv_sec
      alias usec tv_usec

      #
      # Returns the time value as a ruby Time object.
      #
      # @return [Time]
      #   A ruby time object derived from this TimeVal.
      #
      def time
        Time.at(self.tv_sec, self.tv_usec)
      end

      alias to_time time

      #
      # Sets the time value from a ruby Time object
      #
      # @param [Time] new_time
      #   A ruby time object from which to set the time.
      #
      # @return [Time]
      #   Returns the same Time object supplied per convention.
      #
      def time=(new_time)
        self.tv_sec  = new_time.tv_sec
        self.tv_usec = new_time.tv_usec

        return new_time
      end

    end
  end
end
