require 'spec_helper'

describe FileHeader do
  let(:pcap_file) do
    File.open(PCAP_TESTFILE,'rb') do |file|
      file.read
    end
  end

  subject { described_class.new(:raw => pcap_file) }

  it "should parse a pcap file correctly" do
    subject.magic.should == 0xa1b2c3d4
    subject.version_major.should == 2
    subject.version_minor.should == 4
    subject.thiszone.should == 0
    subject.sigfigs.should == 0
    subject.snaplen.should == 96
    subject.linktype.should == 1
  end

  it "should return a file format version string" do
    subject.version.should == "2.4"
  end

  it "should return a DataLink for the linktype using datalink()" do
    subject.datalink.should be_kind_of(DataLink)

    (subject.datalink == :en10mb).should == true
  end
end
