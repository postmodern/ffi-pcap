require 'spec_helper'

describe FFI::PCap::Live do
  describe "packet injection" do
    before(:all) do
      @pcap = FFI::PCap.open_live(
        :device  => PCAP_DEV,
        :promisc => false,
        :timeout => 100,
        :snaplen => 8192
      )
    end

    after(:all) { @pcap.close }

    it "should detect when an invalid argument is supplied" do
      expect { @pcap.inject(Object.new)}.to raise_error(ArgumentError)
      expect { @pcap.inject(nil)}.to raise_error(ArgumentError)
      expect { @pcap.inject(1)}.to raise_error(ArgumentError)
      expect { @pcap.inject([])}.to raise_error(ArgumentError)
      expect { @pcap.inject(:foo => :bar)}.to raise_error(ArgumentError)
      expect {
        @pcap.inject(FFI::MemoryPointer.new(10))
      }.to raise_error(ArgumentError)
    end

    it "should allow injection of a String using inject()" do
      test_data = "A" * 1024

      expect(@pcap.inject(test_data)).to eq(test_data.size)
    end

    it "should allow injection of a Packet using inject()" do
      test_data = "B" * 512

      expect(@pcap.inject(Packet.from_string(test_data))).to eq(test_data.size)
    end
  end
end
