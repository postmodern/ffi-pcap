require 'spec_helper'
require 'wrapper_behaviors'
require 'packet_behaviors'

describe Live do
  before(:each) do
    @pcap = Live.new(
      :device => PCAP_DEV,
      :promisc => true
    )
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "PCap::CaptureWrapper"
  
  it "should support non-blocking mode" do
    @pcap.non_blocking = true
    @pcap.should be_non_blocking
  end

  it "should provide statistics about packets received/dropped" do
    i = 0
    @pcap.loop {|*x| @pcap.stop if (i += 1) == 10 }
    i.should_not == 0
    stats = @pcap.stats
    Stat.should === stats
    stats.received.should > 0
    stats.received.should == 10
  end

  describe "live packets" do
    before(:all) do
      @pcap = Live.new(
        :device => PCAP_DEV,
        :promisc => true
      )
      @pkt = @pcap.next()
    end

    after(:all) do
      @pcap.close
    end
    
    it_should_behave_like "PCap::Packet populated"

  end

  describe "yielding to a block" do
    # Note we also test all the behaviors here together instead of seperately.
    Offline.new(PCAP_TESTFILE) do |this|
      @pcap = this

      it "should be in a ready state in the block" do
        @pcap.should be_ready
        @pcap.should_not be_closed
      end

      it_should_behave_like "PCap::CaptureWrapper"

      @pcap.close
    end
  end
end

