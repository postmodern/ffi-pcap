require 'pcap/ffi'
require 'pcap/data_link'
require 'pcap/handler'

module FFI
  module PCap
    def PCap.open_live(options={})
      device = options[:device]
      promisc = if options[:promisc]
                  1
                else
                  0
                end
      snaplen = (options[:snaplen] || SNAPLEN)
      to_ms = (options[:timeout] || 0)

      ptr = PCap.pcap_open_live(device,snaplen,promisc,to_ms,nil)

      unless ptr
        raise(StandardError,errbuf,caller)
      end

      return Handler.new(ptr)
    end

    def self.open_dead(datalink,snaplen=SNAPLEN)
      datalink = DataLink[datalink]

      return Handler.new(PCap.pcap_open_dead(datalink,snaplen))
    end

  end
end
