require 'spec_helper'

describe DataLink do
  subject { described_class.new(0) }

  it "should map datalink names to datalink layer type values" do
    expect(described_class.name_to_val(:en10mb)).to eq(1)
  end

  it "should map datalink layer type values to datalink names" do
    expect(described_class.val_to_name(1)).to eq("EN10MB")
  end

  it "should be initialized from a pcap datalink value" do
    expect(subject.name).to eq('NULL')
  end

  it "should have a description" do
    expect(subject.description).not_to be_empty
  end

  describe "#initialize" do
    it "should support initialization from a pcap datalink name Symbol" do
      link = described_class.new(:null)

      expect(link.name).to eq('NULL')
    end

    it "should support initialization from a pcap datalink name String" do
      link = described_class.new('en10mb')
      
      expect(link.name).to eq('EN10MB')
    end
  end

  describe "#==" do
    it "should allow equality comparison against numeric values" do
      expect(subject == 0).to eq(true)
      expect(subject == 1).to eq(false)
    end

    it "should allow equality comparison against String names" do
      expect(subject == "null").to eq(true)
      expect(subject == "en10mb").to eq(false)
    end

    it "should allow equality comparison against Symbol names" do
      expect(subject == :null).to eq(true)
      expect(subject == :en10mb).to eq(false)
    end

    it "should allow comparison against another described_class" do
      expect(subject == described_class.new(0)).to eq(true)
      expect(subject == described_class.new(1)).to eq(false)
    end

    it "should still compare correctly against any other object" do
      expect(subject == Object.new).to eq(false)
    end
  end

  it "should convert to an Integer for the DLT value" do
    expect(subject.to_i).to eq(0)
  end

  it "should convert to a String for the DLT name" do
    expect(subject.to_s).to eq('NULL')
  end
end
