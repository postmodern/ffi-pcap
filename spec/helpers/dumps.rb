def dump_path(name)
  File.expand_path(File.join(File.dirname(__FILE__),'..','dumps',"#{name}.pcap"))
end

def load_dump(name)
  PCap.open_offline(dump_path(name))
end
