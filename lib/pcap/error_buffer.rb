module FFI
  module PCap
    class ErrorBuffer < FFI::Buffer

      # Size of the error buffers
      SIZE = 256

      def initialize
        super(SIZE)
      end

      def to_s
        get_string(SIZE)
      end

    end
  end
end
