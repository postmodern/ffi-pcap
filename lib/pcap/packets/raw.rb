require 'pcap/exceptions/unsupported_datalink'
require 'pcap/packets/ethernet'
require 'pcap/packet'

module FFI
  module PCap
    module Packets
      class Raw

        include Packet

        # Datalink
        attr_reader :datalink

        #
        # Creates a new Raw packet around the specified _ptr_
        # with the specified _length_ and _datalink_.
        #
        def initialize(ptr,length,datalink)
          @length = length
          @payload = ptr
          @payload_length = @length

          @datalink = datalink
          @prev = nil
        end

        def size
          @length
        end

        def to_ptr
          @payload.to_ptr
        end

        def next
          case @datalink.value
          when DataLink::EN10MB
            return Ethernet.new(@payload,@payload_length,self)
          else
            raise(UnsupportedDatalink,"the datalink #{@datalink} is not yet supported",caller)
          end
        end

        protected

        #
        # Delegates all additional method calls to the payload.
        #
        def method_missing(name,*arguments,&block)
          @payload.send(name,*arguments,&block)
        end

      end
    end
  end
end
