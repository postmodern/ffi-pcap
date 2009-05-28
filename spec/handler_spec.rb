require 'pcap/handler'

require 'spec_helper'
require 'helpers/dumps'
require 'handler_examples'

describe PCap::Handler do
  describe "offline" do
    before(:all) do
      @pcap = PCap.open_offline(dump_path('simple_tcp'))
    end

    after(:all) do
      @pcap.close
    end

    it_should_behave_like "Handler"
  end

  describe "live" do
    before(:each) do
      @pcap = PCap.open_live(:count => 2)
    end

    after(:each) do
      @pcap.close
    end

    it_should_behave_like "Handler"

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
  end
end
