require 'spec_helper'
require 'wrapper_behaviors'

describe Dead do
  before(:each) do
    @pcap = PCap.open_dead
  end

  after(:each) do
    @pcap.close
  end

  it_should_behave_like "PCap::CommonWrapper"
end

