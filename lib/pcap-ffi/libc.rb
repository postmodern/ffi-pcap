
module FFI
  module PCap
    module CRT
      extend FFI::Library

      begin; ffi_lib 'msvcrt'; rescue LoadError; end
      attach_function :free, [:pointer], :void
    end
  end
end
