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
require 'set'

require_relative 'monitoring'

module Fluent
  # Fluentd filter plugin to analyze configuration usage.
  #
  # For documentation on inspecting parsed configuration elements, see
  # https://www.rubydoc.info/github/fluent/fluentd/Fluent/Config/Element
  class AnalyzeConfigFilter < Filter
    include Fluent::Config
    Fluent::Plugin.register_filter('analyze_config', self)

    module Constants
      # Built-in plugins that are ok to reference in metrics.
      KNOWN_PLUGINS = {
        'filter' => Set[
          'geoip',
          'grep',
          'parser',
          'record_transformer',
          'stdout',
        ],
        'match' => Set[
          'copy',
          'elasticsearch',
          'exec',
          'exec_filter',
          'file',
          'forward',
          'http',
          'kafka',
          'mongo',
          'mongo_replset',
          'null',
          'relabel',
          'rewrite_tag_filter',
          'roundrobin',
          's3',
          'secondary_file',
          'stdout',
          'webhdfs',
        ],
        'source' => Set[
          'dummy',
          'exec',
          'forward',
          'http',
          'monitor_agent',
          'syslog',
          'tail',
          'tcp',
          'udp',
          'unix',
          'windows_eventlog',
        ]
      }.freeze

      # For Google plugins, we collect metrics on the params listed here.
      GOOGLE_PLUGIN_PARAMS = {
        'google_cloud' => %w(
          adjust_invalid_timestamps
          auth_method
          autoformat_stackdriver_trace
          coerce_to_utf8
          detect_json
          enable_monitoring
          gcm_service_address
          grpc_compression_algorithm
          http_request_key
          insert_id_key
          label_map
          labels
          labels_key
          logging_api_url
          monitoring_type
          non_utf8_replacement_string
          operation_key
          private_key_email
          private_key_passphrase
          private_key_path
          project_id
          source_location_key
          span_id_key
          statusz_port
          trace_key
          trace_sampled_key
          use_grpc
          use_metadata_service
          vm_id
          vm_name
          zone
        ),
        'detect_exceptions' => %w(
          languages
          max_bytes
          max_lines
          message
          multiline_flush_interval
          remove_tag_prefix
          stream
        )
      }.freeze
    end

    include self::Constants

    # The root configuration file of google-fluentd package.
    # This only applies to Linux.
    config_param :google_fluentd_config_path,
                 :string,
                 default: '/etc/google-fluentd/google-fluentd.conf'
    # Baseline configuration for comparing with local
    # customizations.
    config_param :google_fluentd_baseline_config_path,
                 :string,
                 default: '/etc/google-fluentd/baseline/google-fluentd.conf'

    def start
      super
      @log = $log # rubocop:disable Style/GlobalVars

      # Initialize the insertID.
      @log.info 'Started the analyze_config plugin to analyze configuration.'
    end

    def parse_config(path)
      data = File.open(path, 'r', &:read)
      fname = File.basename(path)
      basepath = File.dirname(path)
      eval_context = Kernel.binding
      # Override instance_eval so that LiteralParser does not actually
      # evaluate the embedded Ruby, but instead just returns the
      # source string.  See
      # https://github.com/fluent/fluentd/blob/master/lib/fluent/config/literal_parser.rb
      def eval_context.instance_eval(code)
        code
      end
      Fluent::Config::V1Parser.parse(data, fname, basepath, eval_context)
    end

    # Returns a name for identifying plugins we ship by default.
    def default_plugin_name(e)
      case e['@type']
      when 'syslog'
        "#{e.name}/syslog/#{e['protocol_type']}"
      when 'tail'
        "#{e.name}/tail/#{File.basename(e['pos_file'], '.pos')}"
      else
        "#{e.name}/#{e['@type']}"
      end
    end

    # Returns a name for identifying plugins not in our default
    # config.  This should not contain arbitrary user-supplied data.
    def custom_plugin_name(e)
      if KNOWN_PLUGINS.key?(e.name) &&
         KNOWN_PLUGINS[e.name].include?(e['@type'])
        "#{e.name}/#{e['@type']}"
      else
        e.name.to_s
      end
    end

    def embedded_ruby?(e)
      (e.arg.include?('#{') ||
       e.any? { |_, v| v.include?('#{') } ||
       e.elements.any? { |ee| embedded_ruby?(ee) })
    end

    def configure(conf)
      super
      if File.file?(@google_fluentd_config_path) &&
         File.file?(@google_fluentd_baseline_config_path)
        @log.info(
          'google-fluentd configuration file found at' \
          " #{@google_fluentd_config_path}. " \
          'google-fluentd baseline configuration file found at' \
          " #{@google_fluentd_baseline_config_path}. " \
          'google-fluentd Analyzing configuration.')

        # TODO: Add OpenCensus support.
        registry = Monitoring::MonitoringRegistryFactory.create(
          Monitoring::PrometheusMonitoringRegistry.name, nil, nil, nil)

        plugin_usage = registry.counter(
          :stackdriver_enabled_plugins,
          [:plugin_name, :is_default_plugin, :has_customized_config],
          'Enabled plugins')
        config_usage = registry.counter(
          :stackdriver_config_usage,
          [:plugin_name, :param, :is_present, :has_default_value],
          'Parameter usage for Google Cloud plugins')

        config = parse_config(@google_fluentd_config_path)
        baseline_config = parse_config(@google_fluentd_baseline_config_path)

        # Create hash of all baseline elements by their plugin names.
        baseline_elements = Hash[baseline_config.elements.collect do |e|
                                   [default_plugin_name(e), e]
                                 end]
        baseline_google_element = baseline_config.elements.find do |e|
          e['@type'] == 'google_cloud'
        end

        # Look at each top-level config element and see whether it
        # matches the baseline value.
        #
        # Note on custom configurations: If the plugin has a custom
        # value (e.g. if a tail plugin has pos_file
        # /var/lib/google-fluentd/pos/my-custom-value.pos), then the
        # default_plugin_name (e.g. source/tail/my-custom-value) won't
        # be a key in baseline_elements below, so it won't be
        # used.  Instead it will use the custom_plugin_name
        # (e.g. source/tail).
        config.elements.each do |e|
          plugin_name = default_plugin_name(e)
          if baseline_elements.key?(plugin_name)
            is_default_plugin = true
            has_customized_config = (baseline_elements[plugin_name] != e)
          else
            plugin_name = custom_plugin_name(e)
            is_default_plugin = false
            has_customized_config = true
          end
          plugin_usage.increment(
            labels: {
              plugin_name: plugin_name,
              is_default_plugin: is_default_plugin,
              has_customized_config: has_customized_config,
              has_ruby_snippet: embedded_ruby?(e)
            },
            by: 1)

          # Additional metric for Google plugins (google_cloud and
          # detect_exceptions).
          next unless GOOGLE_PLUGIN_PARAMS.key?(e['@type'])
          GOOGLE_PLUGIN_PARAMS[e['@type']].each do |p|
            config_usage.increment(
              labels: {
                plugin_name: e['@type'],
                param: p,
                is_present: e.key?(p),
                is_default_value: (e.key?(p) &&
                                   baseline_google_element.key?(p) &&
                                   e[p] == baseline_google_element[p])
              },
              by: 1)
          end
        end
      else
        @log.info(
          'google-fluentd configuration file does not exist at' \
          " #{@google_fluentd_config_path} or " \
          'google-fluentd baseline configuration file does not exist at' \
          " #{@google_fluentd_baseline_config_path} or " \
          '. Skipping configuration analysis.')
      end
    rescue => e
      # Do not crash the agent due to configuration analysis failures.
      @log.warn(
        'Failed to optionally analyze the google-fluentd configuration' \
        " file. Proceeding anyway. Error: #{e}")
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
