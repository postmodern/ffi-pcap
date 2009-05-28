require 'ffi/struct'

module FFI
  module PCap
    class Stat < FFI::Struct
      layout :ps_recv, :uint,
             :ps_drop, :uint,
             :ps_ifdrop, :uint

      def received
        self[:ps_recv]
      end

      def dropped
        self[:ps_drop]
      end

      def interface_dropped
        self[:ps_ifdrop]
      end
    end
  end
end
