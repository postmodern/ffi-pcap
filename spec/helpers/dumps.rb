def dump_path(filename)
  File.expand_path(File.join(File.dirname(__FILE__), '..', 'dumps', filename))
end

def load_dump(name)
  PCap.open_offline(dump_path(name))
end
