source 'https://rubygems.org'

gemspec

group :test, :development do
  # Required for stats support until opencensus-ruby releases >0.4.0.
  gem 'opencensus',
      github: 'census-instrumentation/opencensus-ruby',
      branch: 'master'
  # Required for stats support until opencensus-ruby-exporter-stackdriver releases
  # >0.2.0.
  gem 'opencensus-stackdriver',
      github: 'census-ecosystem/opencensus-ruby-exporter-stackdriver',
      branch: 'master'
end
