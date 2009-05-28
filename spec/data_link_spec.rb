require 'pcap/data_link'

require 'spec_helper'

describe DataLink do
  before(:all) do
    @datalink = DataLink.new(0)
  end

  it "should be initialized from a pcap datalink value" do
    @datalink.name.should == 'NULL'
  end

  it "should map datalink names to pcap datalink values" do
    DataLink[:en10mb].should == 1
  end

  it "should have a description" do
    @datalink.description.should_not be_empty
  end

  it "should be able to convert to an Integer" do
    @datalink.to_i.should == 0
  end

  it "should be able to convert to a String" do
    @datalink.to_s.should == 'NULL'
  end
end
