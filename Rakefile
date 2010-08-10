load 'tasks/setup.rb'

ensure_in_path 'lib'

task :default => 'spec:run'

PROJ.name='ffi-pcap'
PROJ.authors = ["Postmodern", "Dakrone", "Eric Monti"]
PROJ.email = 'postmodern_mod3@gmail.com'
PROJ.summary     = "FFI bindings for libpcap"
PROJ.description = "Bindings to libpcap via FFI interface in Ruby."
PROJ.url = "http://github.com/sophsec/ffi-pcap"
PROJ.version = File.open("VERSION","r"){|f| f.readline.chomp}
PROJ.readme_file = 'README.md'
PROJ.history_file = 'ChangeLog.md'
PROJ.readme_file = 'README.rdoc'

PROJ.spec.opts += File.read(".specopts").split("\n")

# exclude rcov.rb and external libs from rcov report
PROJ.rcov.opts += [
  "--exclude",  "rcov", 
  "--exclude", "ffi",
  "--exclude", "ffi_dry",
]


depend_on 'ffi', '>= 2.1.1'
depend_on 'ffi_dry', '>= 0.1.9'

