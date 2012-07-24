require 'spec_helper'

describe DataLink do
  subject { described_class.new(0) }

  it "should map datalink names to datalink layer type values" do
    described_class.name_to_val(:en10mb).should == 1
  end

  it "should map datalink layer type values to datalink names" do
    described_class.val_to_name(1).should == "EN10MB"
  end

  it "should be initialized from a pcap datalink value" do
    subject.name.should == 'NULL'
  end

  it "should have a description" do
    subject.description.should_not be_empty
  end

  describe "#initialize" do
    it "should support initialization from a pcap datalink name Symbol" do
      link = described_class.new(:null)

      link.name.should == 'NULL'
    end

    it "should support initialization from a pcap datalink name String" do
      link = described_class.new('en10mb')
      
      link.name.should == 'EN10MB'
    end
  end

  describe "#==" do
    it "should allow equality comparison against numeric values" do
      (subject == 0).should == true
      (subject == 1).should == false
    end

    it "should allow equality comparison against String names" do
      (subject == "null").should == true
      (subject == "en10mb").should == false
    end

    it "should allow equality comparison against Symbol names" do
      (subject == :null).should == true
      (subject == :en10mb).should == false
    end

    it "should allow comparison against another described_class" do
      (subject == described_class.new(0)).should == true
      (subject == described_class.new(1)).should == false
    end

    it "should still compare correctly against any other object" do
      (subject == Object.new).should == false
    end
  end

  it "should convert to an Integer for the DLT value" do
    subject.to_i.should == 0
  end

  it "should convert to a String for the DLT name" do
    subject.to_s.should == 'NULL'
  end
end
