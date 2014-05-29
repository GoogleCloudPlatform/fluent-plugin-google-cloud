$:.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = 'fluent-plugin-google-cloud'
  spec.description   = %q{Fluentd plugin to stream logs to the Google Cloud Platform's logs API, which will make them viewable in the Developer Console's log viewer and can optionally store them in Google Cloud Storage and/or BigQuery.}
  spec.summary       = %q{Fluentd plugin to stream logs to the Google Cloud Platform's logs API}
  spec.homepage      = 'https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud'
  spec.license       = 'APLv2'
  spec.version       = '0.1.0'
  spec.authors       = ['Alex Robinson']
  spec.email         = ['arob@google.com']
  spec.has_rdoc      = false

  spec.files         = `git ls-files`.split('\n')
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'fluentd'
  spec.add_runtime_dependency 'google-api-client', '~> 0.7.1'
end
