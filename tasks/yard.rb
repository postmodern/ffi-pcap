begin
  require 'yard'

  YARD::Rake::YardocTask.new do |t|
    if File.exist?('VERSION')  
      version = "- #{File.read('VERSION')}"
    else  
      version = ""  
    end  
    
    t.files   = ['ChangeLog*','LICENSE*','lib/**/*.rb']
    t.options = [
      '--title',"FFI PCap Documentation #{version}",
      '--protected',
    ]
  end

  task :docs => :yard
rescue LoadError
end

