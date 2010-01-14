require 'spec_helper'

describe DataLink do
  before(:all) do
    @datalink = DataLink.new(0)
  end

  it "should map datalink names to datalink layer type values" do
    DataLink.name_to_val(:en10mb).should == 1
  end

  it "should map datalink layer type values to datalink names" do
    DataLink.val_to_name(1).should == "EN10MB"
  end


  it "should be initialized from a pcap datalink value" do
    @datalink.name.should == 'NULL'
  end

  it "should support initialization from a pcap datalink name symbol" do
    @datalink = DataLink.new(:null)
    DataLink.should === @datalink
  end

  it "should support initialization from a pcap datalink name string" do
    dl = DataLink.new('en10mb')
    DataLink.should === dl
  end

  it "should allow equality comparison against numeric values" do
    (@datalink == 0).should == true
    (@datalink == 1).should == false
  end

  it "should allow equality comparison against String names" do
    (@datalink == "null").should == true
    (@datalink == "en10mb").should == false
  end

  it "should allow equality comparison against Symbol names" do
    (@datalink == :null).should == true
    (@datalink == :en10mb).should == false
  end

  it "should allow comparison against another DataLink" do
    (@datalink == DataLink.new(0)).should == true
    (@datalink == DataLink.new(1)).should == false
  end

  it "should still compare correctly against any other object" do
    (@datalink == Object.new).should == false
  end

  it "should have a description" do
    @datalink.description.should_not be_empty
  end

  it "should convert to an Integer for the DLT value" do
    @datalink.to_i.should == 0
  end

  it "should convert to a String for the DLT name" do
    @datalink.to_s.should == 'NULL'
  end
end
