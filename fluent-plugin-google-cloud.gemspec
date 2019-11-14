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
  gem.version       = '0.7.26'
  gem.authors       = ['Stackdriver Agents Team']
  gem.email         = ['stackdriver-agents@google.com']
  gem.required_ruby_version = Gem::Requirement.new('>= 2.2')

  gem.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  gem.test_files    = gem.files.grep(/^(test)/)
  gem.require_paths = ['lib']

  gem.add_runtime_dependency 'fluentd', '1.6.3'
  gem.add_runtime_dependency 'googleapis-common-protos', '1.3.9'
  gem.add_runtime_dependency 'googleauth', '0.9.0'
  gem.add_runtime_dependency 'google-api-client', '0.30.8'
  gem.add_runtime_dependency 'google-cloud-logging', '1.6.6'
  gem.add_runtime_dependency 'google-protobuf', '3.9.0'
  gem.add_runtime_dependency 'grpc', '1.22.0'
  gem.add_runtime_dependency 'json', '2.2.0'

  gem.add_development_dependency 'mocha', '1.9.0'
  gem.add_development_dependency 'opencensus', '0.5.0'
  gem.add_development_dependency 'opencensus-stackdriver', '0.3.0'
  # Keep this the same as in
  # https://github.com/fluent/fluent-plugin-prometheus/blob/master/fluent-plugin-prometheus.gemspec
  gem.add_development_dependency 'prometheus-client', '< 0.10'
  # TODO(qingling128): Upgrade rake to 11.0+ after the following issues are
  # fixed because rake (11.0+) requires ALL variables to be explicitly
  # initialized.
  # https://github.com/googleapis/google-auth-library-ruby/issues/227
  # https://github.com/farcaller/rly/issues/2
  gem.add_development_dependency 'rake', '10.5.0'
  gem.add_development_dependency 'rubocop', '0.39.0'
  gem.add_development_dependency 'test-unit', '3.3.3'
  gem.add_development_dependency 'webmock', '3.6.2'
end
