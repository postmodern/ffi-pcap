require 'spec_helper'
require 'wrapper_behaviors'
require 'packet_behaviors'

describe Live do
  before(:each) do
    @pcap = Live.new(
      :device => PCAP_DEV,
      :promisc => true,
      :timeout => 1000
    )
    start_traffic_generator()
  end

  after(:each) do
    stop_traffic_generator()
    @pcap.close
  end

  it_should_behave_like "FFI::PCap::CaptureWrapper"
  
  it "should support non-blocking mode" do
    @pcap.non_blocking = true
    expect(@pcap).to be_non_blocking
  end

  it "should provide statistics about packets received/dropped" do
    i = 0

    @pcap.loop {|this,pkt| @pcap.stop if (i += 1) == 10 }

    expect(i).not_to eq(0)

    stats = @pcap.stats
    expect(stats).to be_kind_of(Stat)
    expect(stats.received).to be > 0
    expect(stats.received).to be >= 10
  end

  it "should yield packets with a timestamp using loop()" do
    i = 0
    @pkt = nil

    @pcap.loop(:count => 2) do |this, pkt|
      expect(this).to eq(@pcap)
      expect(pkt).not_to be_nil
      expect(pkt).to be_kind_of(Packet)

      expect(Time.now - pkt.time).not_to be > 1000

      i += 1
    end

    expect(i).to eq(2)
  end

  describe "live packets" do
    before(:all) do
      @pcap = Live.new(
        :device => PCAP_DEV,
        :promisc => true
      )
      @pkt = @pcap.next()
      start_traffic_generator()
    end

    after(:all) do
      stop_traffic_generator()
      @pcap.close
    end
    
    it_should_behave_like "FFI::PCap::Packet populated"
  end

  describe "yielding to a block" do
    # Note we also test all the behaviors here together instead of seperately.
    Offline.new(PCAP_TESTFILE) do |this|
      @pcap = this

      it "should be in a ready state in the block" do
        expect(@pcap).to be_ready
        expect(@pcap).not_to be_closed
      end

      start_traffic_generator()
      
      it_should_behave_like "FFI::PCap::CaptureWrapper"

      stop_traffic_generator()
      @pcap.close
    end
  end
end

