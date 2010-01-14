require 'spec_helper'
require 'wrapper_behaviors'

describe PCap do
  describe "offline" do
    before(:each) do
      @pcap = PCap.open_offline(PCAP_TESTFILE)
    end

    after(:each) do
      @pcap.close
    end

    it_should_behave_like "PCap::CaptureWrapper"

    it "should return a nil from next() if there are no packets left in the dump file" do
      i = 0
      @pcap.loop { i+=1 }
      i.should_not be_nil
      @pcap.next.should be_nil
    end

  end

  describe "live" do
    before(:each) do
      @pcap = PCap.open_live(
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
      stats.received.should > 0
      stats.received.should == 10
    end

  end

  describe "dead" do
    before(:each) do
      @pcap = PCap.open_dead
    end

    after(:each) do
      @pcap.close
    end

    it_should_behave_like "PCap::CommonWrapper"
  end
end

