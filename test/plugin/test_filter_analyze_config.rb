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

require_relative '../helper'
require_relative 'base_test'

require 'fluent/test/driver/filter'
require 'fluent/plugin/filter_analyze_config'

# Unit tests for filter_analyze_config plugin.
class FilterAnalyzeConfigTest < Test::Unit::TestCase
  include BaseTest
  include Fluent::AnalyzeConfigFilter::Constants

  APPLICATION_DEFAULT_CONFIG = ''.freeze

  def setup
    Fluent::Test.setup
  end

  def test_config_file_does_not_exist
    # By default, the FilterTestDriver.new does not set up a config file at:
    # /etc/google-fluentd/google-fluentd.conf. The plugin should still proceed.
    create_driver
    # No exceptions were thrown.
  end

  def test_analyze_config
    create_driver(CONFIG_ANALYZE_CONFIG)

    # Default plugins, with default config.
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'source/syslog/tcp',
      is_default_plugin: true,
      has_customized_config: false,
      has_ruby_snippet: false)
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'source/tail/apache-access',
      is_default_plugin: true,
      has_customized_config: false,
      has_ruby_snippet: false)
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'filter/add_insert_ids',
      is_default_plugin: true,
      has_customized_config: false,
      has_ruby_snippet: false)

    # Default plugins, with custom config.
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'match/google_cloud',
      is_default_plugin: true,
      has_customized_config: true,
      has_ruby_snippet: false)

    # Custom plugins, some with embedded Ruby.
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'filter',
      is_default_plugin: false,
      has_customized_config: true,
      has_ruby_snippet: false)
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'filter/record_transformer',
      is_default_plugin: false,
      has_customized_config: true,
      has_ruby_snippet: true)
    assert_prometheus_metric_value(
      :stackdriver_enabled_plugins,
      1,
      plugin_name: 'match/stdout',
      is_default_plugin: false,
      has_customized_config: true,
      has_ruby_snippet: true)

    # For out_google_cloud, 3 params are present.
    assert_prometheus_metric_value(
      :stackdriver_config_usage,
      1,
      plugin_name: 'google_cloud',
      param: 'adjust_invalid_timestamps',
      is_present: true,
      is_default_value: true)
    assert_prometheus_metric_value(
      :stackdriver_config_usage,
      1,
      plugin_name: 'google_cloud',
      param: 'autoformat_stackdriver_trace',
      is_present: true,
      is_default_value: false)
    assert_prometheus_metric_value(
      :stackdriver_config_usage,
      1,
      plugin_name: 'google_cloud',
      param: 'coerce_to_utf8',
      is_present: true,
      is_default_value: false)
    # The remaining params are not present.
    %w(
      auth_method
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
    ).each do |p|
      assert_prometheus_metric_value(
        :stackdriver_config_usage,
        1,
        plugin_name: 'google_cloud',
        param: p,
        is_present: false,
        is_default_value: false)
    end
  end

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::FilterTestDriver.new(
      Fluent::AnalyzeConfigFilter).configure(conf, true)
  end
end
