require 'pcap/extensions/ffi/struct/array'

module FFI
  module PCap
    module Packet
      def self.included(base)
        base.module_eval do
          # previous packet in the payload
          attr_reader :prev

          def self.release(ptr)
          end
        end
      end

      #
      # Creates a new packet from the specified _ptr_ and the
      # given _prev_ packet.
      #
      def initialize(ptr,prev=nil)
        super(ptr)

        @prev = prev
      end

      #
      # Returns the data payload of the packet.
      #
      def payload
        self.to_ptr + self.size
      end

      #
      # Default method which returns the next packet in the payload.
      #
      def next
        nil
      end
    end
  end
end
