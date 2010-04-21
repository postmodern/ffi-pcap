begin
  require 'yard'

  YARD::Rake::YardocTask.new do |t|
    t.files   = ['lib/**/*.rb']
    t.options = [
      '--protected',
      '--files', 'History.rdoc',
      '--title', 'caper'
    ]
  end

  task :docs => :yard
rescue LoadError
end

