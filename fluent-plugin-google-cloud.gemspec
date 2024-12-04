Gem::Specification.new do |gem|
  gem.name          = 'fluent-plugin-google-cloud'
  gem.description   = <<-DESCRIPTION
   Fluentd plugins for the Stackdriver Logging API, which will make logs
   viewable in the Stackdriver Logs Viewer and can optionally store them
   in Google Cloud Storage and/or BigQuery.
   This is an official Google Ruby gem.
  DESCRIPTION
  gem.summary       = 'fluentd plugins for the Stackdriver Logging API'
  gem.homepage      =
    'https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud'
  gem.license       = 'Apache-2.0'
  gem.version       = '0.13.4'
  gem.authors       = ['Stackdriver Agents Team']
  gem.email         = ['stackdriver-agents@google.com']
  gem.required_ruby_version = Gem::Requirement.new('>= 2.7')

  gem.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  gem.test_files    = gem.files.grep(/^(test)/)
  gem.require_paths = ['lib']

  # NOTE: In order to update the Fluentd version, please update both here and
  # also the fluentd version in
  # https://github.com/GoogleCloudPlatform/google-fluentd/blob/master/config/software/fluentd.rb.
  gem.add_runtime_dependency 'fluentd', '1.16.2'
  gem.add_runtime_dependency 'google-api-client', '0.53.0'
  gem.add_runtime_dependency 'googleapis-common-protos', '1.4.0'
  gem.add_runtime_dependency 'googleauth', '1.3.0'
  gem.add_runtime_dependency 'google-cloud-logging', '2.3.2'
  gem.add_runtime_dependency 'google-cloud-monitoring-v3', '0.10.0'
  gem.add_runtime_dependency 'google-protobuf', '3.25.5'
  gem.add_runtime_dependency 'grpc', '1.65.2'
  gem.add_runtime_dependency 'json', '2.6.3'
  gem.add_runtime_dependency 'opencensus', '0.5.0'
  gem.add_runtime_dependency 'opencensus-stackdriver', '0.4.1'

  # CVE-2023-28120, CVE-2023-22796, CVE-2023-38037: activesupport is a
  # transitive dependency of google-api-client, which has not been updated
  # upstream to a patched version, so we are pinning it here instead.
  gem.add_runtime_dependency 'activesupport', '~> 6.1', '>= 6.1.7.5'

  gem.add_development_dependency 'mocha', '1.9.0'
  # Keep this the same as in
  # https://github.com/fluent/fluent-plugin-prometheus/blob/master/fluent-plugin-prometheus.gemspec
  gem.add_development_dependency 'coveralls', '0.8.23'
  gem.add_development_dependency 'prometheus-client', '< 0.10'
  gem.add_development_dependency 'rake', '13.0.6'
  gem.add_development_dependency 'rubocop', '1.48.1'
  gem.add_development_dependency 'test-unit', '3.3.3'
  gem.add_development_dependency 'webmock', '3.17.1'
end
