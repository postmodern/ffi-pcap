require 'spec_helper'
require 'wrapper_behaviors'

describe Dead do
  before(:each) do
    @pcap = Dead.new()
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "FFI::PCap::CommonWrapper"

  describe "yielding to a block" do
    # Note we also test all the behaviors here together instead of seperately.
    Dead.new() do |this|
      @pcap = this

      it "should be in a ready state in the block" do
        expect(@pcap).to be_ready
        expect(@pcap).not_to be_closed
      end

      it_should_behave_like "FFI::PCap::CommonWrapper"

      @pcap.close
    end
  end
end
