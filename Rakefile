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

desc 'Does rubocop lint and runs tests'
task all: [:rubocop, :test]

task default: :all
