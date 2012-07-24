module FFI
  module PCap
    class InAddr < FFI::Struct

      layout :s_addr, [:uint8, 4]

    end
  end
end
