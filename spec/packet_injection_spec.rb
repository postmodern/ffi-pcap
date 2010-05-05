require 'spec_helper'

describe FFI::PCap::Live do
  describe "packet injection" do
    before(:all) do
      @pcap = FFI::PCap.open_live :device => PCAP_DEV, 
                             :promisc => false,
                             :timeout => 100,
                             :snaplen => 8192
    end

    after(:all) do
      @pcap.close
    end

    it "should detect when an invalid argument is supplied" do
      lambda { @pcap.inject(Object.new)}.should raise_error(ArgumentError)
      lambda { @pcap.inject(nil)}.should raise_error(ArgumentError)
      lambda { @pcap.inject(1)}.should raise_error(ArgumentError)
      lambda { @pcap.inject([])}.should raise_error(ArgumentError)
      lambda { @pcap.inject(:foo => :bar)}.should raise_error(ArgumentError)
      lambda { 
        @pcap.inject(FFI::MemoryPointer.new(10))
      }.should raise_error(ArgumentError)
    end

    it "should allow injection of a String using inject()" do
      test_data = "A" * 1024
      @pcap.inject(test_data).should == test_data.size
    end

    it "should allow injection of a Packet using inject()" do
      test_data = "B" * 512
      @pcap.inject(Packet.from_string(test_data)).should == test_data.size
    end

  end
end
