require 'spec_helper'

describe FileHeader do
  before(:all) do
    @file_header = FileHeader.new( :raw => File.read(PCAP_TESTFILE) )
  end

  it "should parse a pcap file correctly" do
    @file_header.magic.should == 0xa1b2c3d4
    @file_header.version_major.should == 2
    @file_header.version_minor.should == 4
    @file_header.thiszone.should == 0
    @file_header.sigfigs.should == 0
    @file_header.snaplen.should == 96
    @file_header.linktype.should == 1
  end

  it "should return a file format version string" do
    String.should === @file_header.version
    @file_header.version.should == "2.4"
  end

  it "should return a DataLink for the linktype using datalink()" do
    DataLink.should === @file_header.datalink
    (@file_header.datalink == :en10mb).should == true
  end

end
