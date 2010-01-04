module FFI
  # As returned by pcap_stats()
  #
  # See pcap_stat struct in pcap.h.
  module PCap
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

      ds_layout do
        field :ulong, :rx_packets,  :desc => "total packets received"
        field :ulong, :tx_packets,  :desc => "total packets transmitted"
        field :ulong, :rx_bytes,    :desc => "total bytes received"
        field :ulong, :tx_bytes,    :desc => "total bytes transmitted"
        field :ulong, :tx_bytes,    :desc => "total bytes transmitted"
        field :ulong, :rx_errors,   :desc => "bad packets received"
        field :ulong, :tx_errors,   :desc => "packet transmit problems"
        field :ulong, :rx_dropped,  :desc => "no space in Rx buffers"
        field :ulong, :tx_dropped,  :desc => "no space available for Tx"
        field :ulong, :multicast,   :desc => "multicast packets received"
        field :ulong, :collisions

        # detailed rx errors
        field :ulong, :rx_length_errors
        field :ulong, :rx_over_errors,  :desc => "receiver ring buff overflow"
        field :ulong, :rx_crc_errors,   :desc => "recv'd pkt with crc error"
        field :ulong, :rx_frame_errors, :desc => "recv'd frame alignment errors"
        field :ulong, :rx_fifo_errors,  :desc => "recv'r fifo overrun"
        field :ulong, :rx_missed_errors, :desc => "recv'r missed packet"

        # detailed tx_errors
        field :ulong, :tx_aborted_errors
        field :ulong, :tx_carrier_errors
        field :ulong, :tx_fifo_errors
        field :ulong, :tx_heartbeat_errors
        field :ulong, :tx_window_errors
      end
    end
  end
end
