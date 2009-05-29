require 'pcap/handler'

require 'spec_helper'
require 'helpers/dumps'
require 'handler_examples'

describe PCap::Handler do
  describe "offline" do
    before(:each) do
      @pcap = PCap.open_offline(dump_path('simple_tcp'))
    end

    after(:each) do
      @pcap.close
    end

    it_should_behave_like "Handler"

    it "should not support non-blocking mode" do
      @pcap.non_blocking = true
      @pcap.should_not be_non_blocking
    end

    it "should return a nil if there are no packets left in the dump file" do
      @pcap.loop

      header, data = @pcap.next

      header.should be_nil
      data.should be_nil
    end

    it "should raise a ReadError when reading past the end of a dump file" do
      @pcap.loop

      lambda {
        @pcap.next_extra
      }.should raise_error(ReadError)
    end
  end

  describe "live" do
    before(:each) do
      @pcap = PCap.open_live(:count => 2)
    end

    after(:each) do
      @pcap.close
    end

    it_should_behave_like "Handler"

    it "should support non-blocking mode" do
      @pcap.non_blocking = true
      @pcap.should be_non_blocking
    end

    it "should provide statistics about packets received/dropped" do
      @pcap.loop

      stats = @pcap.stats
      stats.received.should > 0
    end
  end

  describe "dead" do
    before(:each) do
      @pcap = PCap.open_dead
    end

    after(:each) do
      @pcap.close
    end

    it "should support non-blocking mode" do
      @pcap.non_blocking = true
      @pcap.should be_non_blocking
    end
  end
end
