module FFI
  module PCap
    class ErrorBuffer < FFI::MemoryPointer

      # Size of the error buffers
      SIZE = 256

      #  Creates a new ErrorBuffer object. Because of wierdness in JRuby
      #  when trying to subclass FFI::Buffer, always use this instead of 
      #  'new()'
      #
      #  See http://github.com/ffi/ffi/issues#issue/27
      def self.create()
        new(SIZE)
      end

      #
      # Creates a new ErrorBuffer object.
      # The argument is nil and is only present for compatability with JRuby.
      #
      # See http://github.com/ffi/ffi/issues#issue/27
      def initialize(arg=nil)
        super(SIZE)
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
