require 'ffi/struct'

module FFI
  module PCap
    class Stat < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :ps_recv,   :uint
        field :ps_drop,   :uint
        field :ps_ifdrop, :uint
      end

    end
  end
end
