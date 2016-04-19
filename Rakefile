#!/usr/bin/env rake

require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'
require 'rubocop/rake_task'

desc 'Run Rubocop to check for style violations'
RuboCop::RakeTask.new

desc 'Run unit tests'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.test_files = FileList['test/plugin/*.rb']
  test.verbose = true
end

# Building the gem will use the local file mode, so ensure it's world-readable.
# https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud/issues/53
desc 'Check plugin file permissions'
task :check_perms do
  plugin = 'lib/fluent/plugin/out_google_cloud.rb'
  mode = File.stat(plugin).mode & 0777
  fail "Unexpected mode #{mode.to_s(8)} for #{plugin}" unless mode == 0644
end

desc 'Run unit tests and RuboCop to check for style violations'
task all: [:test, :rubocop, :check_perms]

task default: :all
