require 'spec_helper'
require 'wrapper_behaviors'

describe Offline do
  before(:each) { @pcap = Offline.new(PCAP_TESTFILE) }

  after(:each) { @pcap.close }

  it_should_behave_like "FFI::PCap::CaptureWrapper"

  it "should return a nil from next() at the end of the dump file" do
    i = 0

    @pcap.loop {|this,pkt| i += 1 }

    expect(i).to be > 0
    expect(@pcap.next).to be_nil
  end

  it "should yield packets with a timestamp using loop()" do
    i = 0
    @pkt = nil

    @pcap.loop(:count => 2) do |this,pkt|
      expect(this).to eq(@pcap)

      expect(pkt).not_to be_nil
      expect(pkt).to be_kind_of(Packet)
      expect(pkt.time.to_i).to be > 0

      i+=1
    end
    expect(i).to eq(2)
  end

  it "should supply a file version" do
    expect(@pcap.file_version).to match(/^\d+\.\d+$/)
  end

  it "should indicate whether it is endian swapped" do
    expect([true,false].include?(@pcap.swapped?)).to eq(true)
  end

  describe "yielding to a block" do
    # Note we also test all the behaviors here together instead of seperately.
    Offline.new(PCAP_TESTFILE) do |this|
      @pcap = this

      it "should be in a ready state in the block" do
        expect(@pcap).to be_ready
        expect(@pcap).not_to be_closed
      end

      it_should_behave_like "FFI::PCap::CaptureWrapper"

      @pcap.close
    end
  end
end

