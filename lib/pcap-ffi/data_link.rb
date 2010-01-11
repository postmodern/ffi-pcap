module FFI
  module PCap
    class DataLink

      # Several DLT names harvested out of the pcap-bpf.h header file. These
      # are in alphabetical order. Their Array index _does_ _not_ match their 
      # pcap DLT value.
      #
      # Don't use this Array for anything except quick reference.  Use the 
      # 'lookup' class methods for actually resolving name to value 
      # mappings or such.
      SOME_DLTS = %w[A429 A653_ICM AIRONET_HEADER APPLE_IP_OVER_IEEE1394 
      ARCNET ARCNET_LINUX ATM_CLIP ATM_RFC1483 AURORA AX25 BACNET_MS_TP 
      BLUETOOTH_HCI_H4 BLUETOOTH_HCI_H4_WITH_PHDR CAN20B CHAOS CHDLC CISCO_IOS 
      C_HDLC DOCSIS ECONET EN10MB EN3MB ENC ERF ERF_ETH ERF_POS FDDI FRELAY 
      GCOM_SERIAL GCOM_T1E1 GPF_F GPF_T GPRS_LLC HHDLC IBM_SN IBM_SP IEEE802 
      IEEE802_11 IEEE802_11_RADIO IEEE802_11_RADIO_AVS IEEE802_15_4 
      IEEE802_15_4_LINUX IEEE802_16_MAC_CPS IEEE802_16_MAC_CPS_RADIO IPFILTER 
      IPMB IP_OVER_FC JUNIPER_ATM1 JUNIPER_ATM2 JUNIPER_CHDLC JUNIPER_ES 
      JUNIPER_ETHER JUNIPER_FRELAY JUNIPER_GGSN JUNIPER_ISM JUNIPER_MFR 
      JUNIPER_MLFR JUNIPER_MLPPP JUNIPER_MONITOR JUNIPER_PIC_PEER JUNIPER_PPP 
      JUNIPER_PPPOE JUNIPER_PPPOE_ATM JUNIPER_SERVICES JUNIPER_ST JUNIPER_VP 
      LINUX_IRDA LINUX_LAPD LINUX_PPP_WITHDIRECTION LINUX_SLL LOOP LTALK MFR 
      MTP2 MTP2_WITH_PHDR MTP3 NULL OLD_PFLOG PCI_EXP PFLOG PFSYNC PPI PPP 
      PPP_BSDOS PPP_ETHER PPP_PPPD PPP_SERIAL PPP_WITH_DIRECTION PRISM_HEADER 
      PRONET RAIF1 RAW REDBACK_SMARTEDGE RIO SCCP SITA SLIP SLIP_BSDOS SUNATM 
      SYMANTEC_FIREWALL TZSP USB USB_LINUX USER0 USER1 USER10 USER11 USER12 
      USER13 USER14 USER15 USER2 USER3 USER4 USER5 USER6 USER7 USER8 USER9]

      # Uses the pcap_datalnk_* functions to lookup a datalink name and value 
      # pair.
      # 
      # @param [String, Symbol or Integer] l
      #   The name or value to lookup. A Symbol is converted to String. Names 
      #   are case-insensitive.
      #
      # @return Array
      #   A 2-element array containing [value, name]. Both elements are nil
      #   if the lookup failed.
      #
      def self.lookup(l)
        val, name = nil
        l = l.to_s if l.kind_of? Symbol

        case l
        when String
          if v=name_to_val(l)
            name = val_to_name(v)  # get the canonical name
            val = v
          end
        when Integer
          name = val_to_name(l)
          val = l
        else
          raise(ArgumentError, "lookup takes either a String or Integer")
        end
        return [val, name]
      end

      # Translates a data link type name, which is a DLT_ name with the DLT_ 
      # removed, to the corresponding data link type numeric value.
      #
      # @param [String or Symbol] n
      # The name to lookup. Names are case-insensitive.
      #
      # @return [Integer or nil] 
      #   The numeric value for the datalink name or nil on failure.
      def self.name_to_val(n)
        n = n.to_s if n.kind_of?(Symbol)
        if (v=PCap.pcap_datalink_name_to_val(n)) >= 0
          return v
        end
      end

      # Translates a data link type  value  to  the corresponding data link 
      # type name.
      #
      # @return [String or nil]
      #   The string name of the data-link or nil on failure.
      # 
      def self.val_to_name(v)
        PCap.pcap_datalink_val_to_name(v)
      end

      # @param [String, Symbol or Integer] l
      #   The name or value to lookup. A Symbol is converted to String. Names 
      #   are case-insensitive.
      def self.describe(l)
        l = l.to_s if l.kind_of?(Symbol)
        l = PCap.pcap_datalink_name_to_val(l) if l.kind_of?(String) 
        PCap.pcap_datalink_val_to_description(l)
      end
      
      # PCap datalink numeric value
      attr_reader :value

      # Creates a new DataLink object with the specified value or name.
      # The canonical name and value are looked up automatically. 
      #
      # @param [String or Integer] arg
      #   Arg can be a string or number which will be used to look up the
      #   datalink.
      #
      # @raises ArgumentError
      #   An exception is raised if a name is supplied and a lookup for its
      #   value fails or if the arg parameter is an invalid type.
      #
      def initialize(arg)
        if arg.kind_of? String or arg.kind_of? Symbol
          unless @value = self.class.name_to_val(arg.to_s)
            raise(ArgumentError, "Invalid DataLink: #{arg.to_s}")
          end
        elsif arg.kind_of? Numeric
          @value = arg
        else
          raise(ArgumentError, "Invalid DataLink: #{arg.inspect}")
        end
      end

      def ==(other)
        case other
        when Integer
          return (self.value == other)
        when Symbol
          return (@value == self.class.name_to_val(other.to_s))
        when String
          return (@value == self.class.name_to_val(other))
        when other.kind_of?(DataLink)
          return (self.value == other.value)
        else
          return false
        end
      end

      def <=>(other)
        self.value <=> other.value
      end

      # Returns the description of the datalink.
      def description
        @desc ||= self.class.describe(@value)
      end

      alias desc description

      alias describe description

      # Returns the canonical String name of the DataLink object
      def name
        @name ||= self.class.val_to_name(@value)
      end

      alias to_i value
    end
  end
end
