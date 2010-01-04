module FFI
  module PCap
    class Stat < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :ps_recv,   :uint
        field :ps_drop,   :uint
        field :ps_ifdrop, :uint
      end

      alias received ps_recv
      alias dropped ps_drop
      alias interface_dropped ps_ifdrop

    end
  end
end
