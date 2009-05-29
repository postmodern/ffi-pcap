module FFI
  module PCap
    class DataLink

      NULL = 0        # BSD loopback encapsulation
      EN10MB = 1      # Ethernet (10Mb)
      EN3MB = 2       # Experimental Ethernet (3Mb)
      AX25 = 3        # Amateur Radio AX.25
      PRONET = 4      # Proteon ProNET Token Ring
      CHAOS = 5       # Chaos
      IEEE802 = 6     # 802.5 Token Ring
      ARCNET = 7      # ARCNET, with BSD-style header
      SLIP = 8        # Serial Line IP
      PPP = 9         # Point-to-point Protocol
      FDDI = 10       # FDDI

      # PCap datalink numeric value
      attr_reader :value

      # DataLink name
      attr_reader :name

      #
      # Creates a new DataLink object with the specified _value_.
      #
      def initialize(value)
        @value = value
        @name = PCap.pcap_datalink_val_to_name(@value)
      end

      def self.[](name)
        PCap.pcap_datalink_name_to_val(name.to_s.downcase)
      end

      #
      # Returns the description of the datalink.
      #
      def description
        PCap.pcap_datalink_val_to_description(@value)
      end

      #
      # Returns the numeric value of the datalink.
      #
      def to_i
        @value
      end

      #
      # Returns the String form of the datalink.
      #
      def to_s
        @name
      end

      #
      # Inspects the datalink.
      #
      def inspect
        "#<#{self.class}: #{@name}>"
      end

    end
  end
end
