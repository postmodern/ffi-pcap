require 'pcap_ffi/ffi'
require 'pcap_ffi/data_link'
require 'pcap_ffi/if'
require 'pcap_ffi/handler'
require 'pcap_ffi/error_buffer'

module FFI
  module PCap
    def PCap.lib_version
      PCap.pcap_lib_version
    end

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

      PCap.pcap_freealldevs(node)
      return nil
    end

    def PCap.open_live(options={},&block)
      device = options[:device]
      errbuf = ErrorBuffer.new

      unless device
        unless (device = PCap.pcap_lookupdev(errbuf))
          raise(RuntimeError,errbuf.to_s,caller)
        end
      end

      promisc = if options[:promisc]
                  1
                else
                  0
                end
      snaplen = (options[:snaplen] || Handler::SNAPLEN)
      to_ms = (options[:timeout] || 0)

      ptr = PCap.pcap_open_live(device,snaplen,promisc,to_ms,errbuf)

      if ptr.null?
        raise(StandardError,errbuf.to_s,caller)
      end

      return Handler.new(ptr,options,&block)
    end

    def PCap.open_dead(datalink,options={})
      datalink = DataLink[datalink]
      snaplen = (options[:snaplen] || Handler::SNAPLEN)

      return Handler.new(PCap.pcap_open_dead(datalink,snaplen),options)
    end

    def PCap.open_offline(path,options={})
      path = File.expand_path(path)
      errbuf = ErrorBuffer.new

      ptr = PCap.pcap_open_offline(path,errbuf)

      if ptr.null?
        raise(StandardError,errbuf.to_s,caller)
      end

      return Handler.new(ptr,options)
    end
  end
end
