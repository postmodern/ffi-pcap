require 'spec_helper'
require 'wrapper_behaviors'

describe Dead do
  before(:each) do
    @pcap = Dead.new()
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "PCap::CommonWrapper"

  describe "yielding to a block" do
    # Note we also test all the behaviors here together instead of seperately.
    before(:all) do
      @pcap=nil
      @ret = Dead.new do |this|
        this.should_not be_nil
        this.should_not be_closed
        Dead.should === this
        @pcap = this
      end
      @ret.should == @pcap
    end

    after(:all) do
      @pcap.close
    end

    it_should_behave_like "PCap::CommonWrapper"
  end

end

