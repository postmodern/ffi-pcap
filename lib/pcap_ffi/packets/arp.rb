require 'pcap_ffi/packets/typedefs'
require 'pcap_ffi/mac_addr'
require 'pcap_ffi/in_addr'
require 'pcap_ffi/packet'

require 'ffi'

module FFI
  module PCap
    module Packets
      # Note that ARP only supports Ethernet, ipv4 right now
      class Arp < FFI::Struct

        include Packet

        HW_ETHERNET = 0x0001
        PROTCOL_IP  = 0x0002
        OP_REQUEST = 0x0001
        OP_REPLY   = 0x0002

        layout :h_type,     [NativeType::UINT8, 2],
               :p_type,     [NativeType::UINT8, 2],
               :h_len,      :uint8,
               :p_len,      :uint8,
               :operation,  [NativeType::UINT8, 2],
               :sender_mac, MACAddr,
               :sender_ip,  InAddr,
               :dest_mac,   MACAddr,
               :dest_ip,    InAddr

        #
        # Returns ARP hardware type
        #
        def hardware_type
          self[:h_type].to_endian(:big)
        end

        #
        # Returns ARP protocol type
        #
        def protocol_type
          self[:p_type].to_endian(:big)
        end

        #
        # Returns true if ARP request hardware type is Ethernet
        #
        def hardware_ethernet?
          self.hardware_type == HW_ETHERNET
        end

        #
        # Returns true if ARP request protocol type is IP
        #
        def protocol_ip?
          self.protocol_type == PROTOCOL_IP
        end

        #
        # Returns the ARP operation
        #
        def operation
          self[:operation].to_endian(:big)
        end

        #
        # Returns true if it was an ARP request operation
        # 
        def request?
          self.operation == OP_REQUEST
        end

        #
        # Returns true if it was an ARP reply operation
        # 
        def reply?
          self.operation == OP_REPLY
        end

        #
        # Returns the source MAC address.
        #
        def src_mac
          self[:sender_mac]
        end

        #
        # Returns the destination MAC address.
        #
        def dest_mac
          self[:dest_mac]
        end

        #
        # Returns the source IP address.
        #
        def src_ip
          self[:sender_ip]
        end

        #
        # Returns the destination IP address.
        #
        def dest_ip
          self[:dest_ip]
        end

      end
    end
  end
end
