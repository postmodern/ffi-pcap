require 'ffi'

module FFI
  module PCap
    class ErrorBuffer < FFI::Buffer

      # Size of the error buffers
      SIZE = 256

      #
      # Creates a new ErrorBuffer object.
      #
      def initialize
        super(SIZE)
      end

      #
      # Returns the error message within the error buffer.
      #
      def to_s
        get_string(SIZE)
      end

    end
  end
end
