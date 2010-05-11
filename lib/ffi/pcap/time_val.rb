module FFI
  module PCap
    class TimeVal < FFI::Struct

      include FFI::DRY::StructHelper

      dsl_layout do
        field :tv_sec, :time_t
        field :tv_usec, :suseconds_t
      end

      def initialize(*args)
        if args.size == 1 and (t=args[0]).kind_of?(Time)
          self.time = t
        else
          super(*args)
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
      # @param [Time] t
      #   A ruby time object from which to set the time.
      #
      # @return [Time]
      #   Returns the same Time object supplied per convention.
      #
      def time=(t)
        self.tv_sec = t.tv_sec
        self.tv_usec = t.tv_usec
        return t
      end

    end
  end
end
