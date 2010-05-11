require 'socket'

module FFI
  module PCap
    #
    # contains AF_* constants culled from Ruby's ::Socket
    #
    module AF
      include ::FFI::DRY::ConstMap

      slurp_constants(::Socket, "AF_")

      def self.list
        @@list ||= super()
      end
    end
  end
end
