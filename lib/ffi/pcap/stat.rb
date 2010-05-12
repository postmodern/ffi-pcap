require 'ffi/pcap/stat_ex'

module FFI
  module PCap
    #
    # As returned by `pcap_stats`.
    #
    # See `pcap_stat` struct in `pcap.h`.
    #
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
  end
end
