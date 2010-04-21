
module Caper
  module CRT
    extend FFI::Library

    ffi_lib FFI::Library::LIBC

    typedef :ulong, :size_t  # not all platforms have this set for FFI

    attach_function :free, [:pointer], :void
    attach_function :memcpy, [:pointer, :pointer, :size_t], :pointer
  end
end
