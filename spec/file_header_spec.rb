require 'spec_helper'

describe FileHeader do
  let(:pcap_file) do
    File.open(PCAP_TESTFILE,'rb') do |file|
      file.read
    end
  end

  subject { described_class.new(:raw => pcap_file) }

  it "should parse a pcap file correctly" do
    expect(subject.magic).to eq(0xa1b2c3d4)
    expect(subject.version_major).to eq(2)
    expect(subject.version_minor).to eq(4)
    expect(subject.thiszone).to eq(0)
    expect(subject.sigfigs).to eq(0)
    expect(subject.snaplen).to eq(96)
    expect(subject.linktype).to eq(1)
  end

  it "should return a file format version string" do
    expect(subject.version).to eq("2.4")
  end

  it "should return a DataLink for the linktype using datalink()" do
    expect(subject.datalink).to be_kind_of(DataLink)

    expect(subject.datalink == :en10mb).to eq(true)
  end
end
