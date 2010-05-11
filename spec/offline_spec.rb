require 'spec_helper'
require 'wrapper_behaviors'

describe Offline do
  before(:each) do
    @pcap = Offline.new(PCAP_TESTFILE)
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "FFI::PCap::CaptureWrapper"

  it "should return a nil from next() at the end of the dump file" do
    i = 0
    @pcap.loop {|this,pkt| i+=1 }
    i.should > 0
    @pcap.next.should be_nil
  end

  it "should yield packets with a timestamp using loop()" do
    i = 0
    @pkt = nil
    @pcap.loop(:count => 2) do |this, pkt|
      this.should == @pcap
      pkt.should_not be_nil
      Packet.should === pkt
      pkt.time.to_i.should > 0
      i+=1
    end
    i.should == 2
  end

  it "should supply a file version" do
    @pcap.file_version.should =~ /^\d+\.\d+$/
  end

  it "should indicate whether it is endian swapped" do
    [true,false].include?(@pcap.swapped?).should == true
  end

  describe "yielding to a block" do

    # Note we also test all the behaviors here together instead of seperately.
    Offline.new(PCAP_TESTFILE) do |this|
      @pcap = this

      it "should be in a ready state in the block" do
        @pcap.should be_ready
        @pcap.should_not be_closed
      end

      it_should_behave_like "FFI::PCap::CaptureWrapper"

      @pcap.close
    end

  end
end

