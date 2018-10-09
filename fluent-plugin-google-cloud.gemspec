Gem::Specification.new do |gem|
  gem.name          = 'fluent-plugin-google-cloud'
  gem.description   = <<-eos
   Fluentd plugins for the Stackdriver Logging API, which will make logs
   viewable in the Stackdriver Logs Viewer and can optionally store them
   in Google Cloud Storage and/or BigQuery.
   This is an official Google Ruby gem.
eos
  gem.summary       = 'fluentd plugins for the Stackdriver Logging API'
  gem.homepage      =
    'https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud'
  gem.license       = 'Apache-2.0'
  gem.version       = '0.7.0'
  gem.authors       = ['Stackdriver Agents Team']
  gem.email         = ['stackdriver-agents@google.com']
  gem.required_ruby_version = Gem::Requirement.new('>= 2.2')

  gem.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  gem.test_files    = gem.files.grep(/^(test)/)
  gem.require_paths = ['lib']

  gem.add_runtime_dependency 'fluentd', '1.2.5'
  gem.add_runtime_dependency 'googleapis-common-protos', '1.3.7'
  gem.add_runtime_dependency 'googleauth', '0.6.6'
  gem.add_runtime_dependency 'google-api-client', '0.23.9'
  gem.add_runtime_dependency 'google-cloud-logging', '1.5.4'
  gem.add_runtime_dependency 'google-protobuf', '3.6.1'
  gem.add_runtime_dependency 'grpc', '1.8.3'
  gem.add_runtime_dependency 'json', '2.1.0'

  gem.add_development_dependency 'mocha', '~> 1.1'
  gem.add_development_dependency 'prometheus-client', '~> 0.7.1'
  gem.add_development_dependency 'rake', '~> 10.3'
  gem.add_development_dependency 'rubocop', '~> 0.39.0'
  gem.add_development_dependency 'test-unit', '~> 3.0'
  gem.add_development_dependency 'webmock', '~> 2.3.1'
end
