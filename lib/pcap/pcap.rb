require 'pcap/ffi'
require 'pcap/data_link'
require 'pcap/if'
require 'pcap/handler'
require 'pcap/error_buffer'

module FFI
  module PCap
    def PCap.device
      errbuf = ErrorBuffer.new

      unless (name = PCap.pcap_lookupdev(errbuf))
        raise(StandardError,errbuf.to_s,caller)
      end

      return name
    end

    def PCap.each_device(&block)
      devices = MemoryPointer.new(:pointer)
      errbuf = ErrorBuffer.new

      PCap.pcap_findalldevs(devices,errbuf)
      node = devices.get_pointer(0)

      if node.null?
        raise(StandardError,errbuf.to_s,caller)
      end

      device = IF.new(node)

      until device
        block.call(device) if block
        device = device.next
      end

      PCap.pcap_freealldevs(devices.get_pointer(0))
      return nil
    end

    def PCap.open_live(options={})
      device = options[:device]
      promisc = if options[:promisc]
                  1
                else
                  0
                end
      snaplen = (options[:snaplen] || Handler::SNAPLEN)
      to_ms = (options[:timeout] || 0)
      errbuf = ErrorBuffer.new

      ptr = PCap.pcap_open_live(device,snaplen,promisc,to_ms,nil)

      if ptr.null?
        raise(StandardError,errbuf.to_s,caller)
      end

      return Handler.new(ptr)
    end

    def PCap.open_dead(datalink,snaplen=Handler::SNAPLEN)
      datalink = DataLink[datalink]

      return Handler.new(PCap.pcap_open_dead(datalink,snaplen))
    end

    def PCap.open_offline(path)
      path = File.expand_path(path)
      errbuf = ErrorBuffer.new

      ptr = PCap.pcap_open_offline(path,errbuf)

      if ptr.null?
        raise(StandardError,errbuf.to_s,caller)
      end

      return Handler.new(ptr)
    end
  end
end
