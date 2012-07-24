module FFI
  module PCap
    class ErrorBuffer < FFI::Buffer

      # Size of the error buffers
      SIZE = 256

      #
      # Creates a new {ErrorBuffer} object.
      #
      # @param [FFI::Pointer] ptr
      #   Optional pointer to an existing {ErrorBuffer}.
      #
      def initialize(ptr=nil)
        if ptr then super(ptr)
        else        super(SIZE)
        end
      end

      #
      # Returns the error message within the error buffer.
      #
      def to_s
        get_string(0)
      end

    end
  end
end
