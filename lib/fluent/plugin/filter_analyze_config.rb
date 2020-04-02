# Copyright 2020 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'fileutils'
require 'fluent/config'
require 'fluent/config/v1_parser'

module Fluent
  # Fluentd filter plugin to analyze configuration usage.
  class AnalyzeConfigFilter < Filter
    include Fluent::Config
    Fluent::Plugin.register_filter('analyze_config', self)

    # Constants.
    module Constants
      # The root configuration file of google-fluentd package.
      # This only applies to Linux.
      GOOGLE_FLUENTD_CONFIG_PATH =
        '/etc/google-fluentd/google-fluentd.conf'.freeze
    end

    include self::Constants

    def start
      super
      @log = $log # rubocop:disable Style/GlobalVars

      # Initialize the insertID.
      @log.info 'Started the analyze_config plugin to analyze configuration.'
    end

    def configure(conf)
      super
      if File.file?(GOOGLE_FLUENTD_CONFIG_PATH)
        @log.info(
          'google-fluentd configuration file found at' \
          " #{GOOGLE_FLUENTD_CONFIG_PATH}. Analyzing configuration.")
        data = File.open(GOOGLE_FLUENTD_CONFIG_PATH, 'r', &:read)
        fname = File.basename(GOOGLE_FLUENTD_CONFIG_PATH)
        basepath = File.dirname(GOOGLE_FLUENTD_CONFIG_PATH)
        eval_context = Kernel.binding
        parsed_fluentd_config = Fluent::Config::V1Parser.parse(
          data, fname, basepath, eval_context)
        @log.info(
          "Parsed configuration: #{parsed_fluentd_config.inspect}")
        # TODO: Take the parsed configuration and do some analysis here.
        # Start the Open Telemetry module to ingest the metrics.
      else
        @log.info(
          'google-fluentd configuration file does not exist at' \
          " #{GOOGLE_FLUENTD_CONFIG_PATH}. Skipping configuration analysis.")
      end
    rescue
      # Do not crash the agent due to configuration analysis failures.
      @log.warn(
        'Failed to optionally analyze the google-fluentd configuration' \
        ' file. Proceeding anyway.')
    end

    def shutdown
      super
    end

    # rubocop:disable Lint/UnusedMethodArgument
    def filter(tag, time, record)
      # Skip the actual filtering process.
      record
    end
    # rubocop:enable Lint/UnusedMethodArgument
  end
end
