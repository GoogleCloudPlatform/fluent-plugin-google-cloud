Gem::Specification.new do |gem|
  gem.name          = 'fluent-plugin-google-cloud'
  gem.description   = <<-eos
   Fluentd output plugin for the Stackdriver Logging API, which will make
   logs viewable in the Developer Console's log viewer and can optionally
   store them in Google Cloud Storage and/or BigQuery.
   This is an official Google Ruby gem.
eos
  gem.summary       = 'fluentd output plugin for the Stackdriver Logging API'
  gem.homepage      = \
    'https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud'
  gem.license       = 'Apache-2.0'
  gem.version       = '0.5.2'
  gem.authors       = ['Todd Derr', 'Alex Robinson']
  gem.email         = ['salty@google.com']
  gem.required_ruby_version = Gem::Requirement.new('>= 2.0')

  gem.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  gem.test_files    = gem.files.grep(/^(test)/)
  gem.require_paths = ['lib']

  gem.add_runtime_dependency 'fluentd', '~> 0.10', '<= 0.13'
  gem.add_runtime_dependency 'google-api-client', '> 0.9'
  gem.add_runtime_dependency 'googleauth', '~> 0.4'
  gem.add_runtime_dependency 'json', '~> 1.8'

  gem.add_development_dependency 'mocha', '~> 1.1'
  gem.add_development_dependency 'rake', '~> 10.3'
  gem.add_development_dependency 'rubocop', '~> 0.35.0'
  gem.add_development_dependency 'webmock', '~> 1.17'
  gem.add_development_dependency 'test-unit', '~> 3.0'
end
