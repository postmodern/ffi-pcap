require 'pcap_ffi/packets/icmp/data'

require 'ffi'

module FFI
  module PCap
    module Packets
      class ICMPv4 < FFI::Struct

        layout :type, :uint8,
               :code, :uint8,
               :checksum, :uint16,
               :data, ICMPv4::Data

        def type
          self[:type]
        end

        def code
          self[:code]
        end

        def echo
          self[:data][:echo]
        end

        def echo_id
          echo[:id]
        end

        def echo_sequence
          echo[:sequence]
        end

        def mtu
          self[:data][:frag][:mtu]
        end

      end
    end
  end
end
