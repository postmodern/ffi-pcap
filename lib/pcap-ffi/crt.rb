
module FFI
  module PCap
    module CRT
      extend FFI::Library

      begin
        ffi_lib 'msvcrt'
      rescue LoadError
      end

      typedef :ulong, :size_t  # not all platforms have this set for FFI

      attach_function :free, [:pointer], :void
      attach_function :memcpy, [:pointer, :pointer, :size_t], :pointer
    end
  end
end
