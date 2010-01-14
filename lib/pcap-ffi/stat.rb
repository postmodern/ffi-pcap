module FFI
  module PCap

    # As returned by pcap_stats()
    #
    # See pcap_stat struct in pcap.h.
    class Stat < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :ps_recv,   :uint, :desc => "number of packets received"
        field :ps_drop,   :uint, :desc => "numer of packets dropped"
        field :ps_ifdrop, :uint, :desc => "drops by interface (not yet supported)"
        # bs_capt field intentionally left off (WIN32 only)
      end

      alias received ps_recv
      alias dropped ps_drop
      alias interface_dropped ps_ifdrop

    end

    # As returned by pcap_stats_ex() (MSDOS only)
    #
    # See pcap_stat_ex struct in pcap.h
    class StatEx < FFI::Struct
      include FFI::DRY::StructHelper

      dsl_layout do
        field :rx_packets,  :ulong, :desc => "total packets received"
        field :tx_packets,  :ulong, :desc => "total packets transmitted"
        field :rx_bytes,    :ulong, :desc => "total bytes received"
        field :tx_bytes,    :ulong, :desc => "total bytes transmitted"
        field :tx_bytes,    :ulong, :desc => "total bytes transmitted"
        field :rx_errors,   :ulong, :desc => "bad packets received"
        field :tx_errors,   :ulong, :desc => "packet transmit problems"
        field :rx_dropped,  :ulong, :desc => "no space in Rx buffers"
        field :tx_dropped,  :ulong, :desc => "no space available for Tx"
        field :multicast,   :ulong, :desc => "multicast packets received"
        field :collisions,  :ulong

        # detailed rx errors
        field :rx_length_errors, :ulong
        field :rx_over_errors,   :ulong, :desc => "ring buff overflow"
        field :rx_crc_errors,    :ulong, :desc => "pkt with crc error"
        field :rx_frame_errors,  :ulong, :desc => "frame alignment errors"
        field :rx_fifo_errors,   :ulong, :desc => "fifo overrun"
        field :rx_missed_errors, :ulong, :desc => "missed packet"

        # detailed tx_errors
        field :tx_aborted_errors,   :ulong
        field :tx_carrier_errors,   :ulong
        field :tx_fifo_errors,      :ulong
        field :tx_heartbeat_errors, :ulong
        field :tx_window_errors,    :ulong
      end
    end
  end
end
