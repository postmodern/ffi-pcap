require 'ffi/struct'

module FFI
  module PCap
    class Stat < FFI::Struct
      layout :ps_recv, :uint,
             :ps_drop, :uint,
             :ps_ifdrop, :uint
    end
  end
end
