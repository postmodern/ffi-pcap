module FFI
  module PCap
    module CRT
      extend FFI::Library

      ffi_lib FFI::Library::LIBC

      attach_function :free, [:pointer], :void
      attach_function :memcpy, [:pointer, :pointer, :size_t], :pointer
    end
  end
end
