# Copyright 2016 Google Inc. All rights reserved.
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

# Enable coveralls for plugin test coverage analysis.
require 'coveralls'
Coveralls.wear!

require 'google/apis'
require 'helper'
require 'mocha/test_unit'
require 'webmock/test_unit'
require 'prometheus/client'

require_relative 'constants'

module Monitoring
  # Prevent OpenCensus from writing to the network.
  class OpenCensusMonitoringRegistry
    def export
      nil
    end
  end
end

# Unit tests for Google Cloud Logging plugin
module BaseTest
  include Asserts
  include Constants

  def setup
    Fluent::Test.setup
    # delete environment variables that googleauth uses to find credentials.
    ENV.delete(CREDENTIALS_PATH_ENV_VAR)
    # service account env.
    ENV.delete(PRIVATE_KEY_VAR)
    ENV.delete(CLIENT_EMAIL_VAR)
    ENV.delete(PROJECT_ID_VAR)
    # authorized_user env.
    ENV.delete(CLIENT_ID_VAR)
    ENV.delete(CLIENT_SECRET_VAR)
    ENV.delete(REFRESH_TOKEN_VAR)
    # home var, which is used to find $HOME/.gcloud/...
    ENV.delete('HOME')

    # Unregister Prometheus metrics.
    registry = Prometheus::Client.registry
    registry.unregister(:stackdriver_successful_requests_count)
    registry.unregister(:stackdriver_failed_requests_count)
    registry.unregister(:stackdriver_ingested_entries_count)
    registry.unregister(:stackdriver_dropped_entries_count)
    registry.unregister(:stackdriver_retried_entries_count)

    setup_auth_stubs
    @logs_sent = []
  end

  # Shared tests.

  def test_configure_service_account_application_default
    setup_gce_metadata_stubs
    d = create_driver
    assert_equal HOSTNAME, d.instance.vm_name
  end

  def test_configure_service_account_private_key
    # Using out-of-date config method.
    exception_count = 0
    begin
      create_driver(PRIVATE_KEY_CONFIG)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Please remove configuration parameters'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_configure_logging_api_url
    setup_gce_metadata_stubs
    {
      APPLICATION_DEFAULT_CONFIG => DEFAULT_LOGGING_API_URL,
      CUSTOM_LOGGING_API_URL_CONFIG => CUSTOM_LOGGING_API_URL
    }.each do |(config, url)|
      d = create_driver(config)
      assert_equal url, d.instance.instance_variable_get(:@logging_api_url)
    end
  end

  def test_configure_custom_metadata
    setup_no_metadata_service_stubs
    d = create_driver(CUSTOM_METADATA_CONFIG)
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
  end

  def test_configure_metadata_missing_parts_on_other_platforms
    setup_no_metadata_service_stubs
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    [[CONFIG_MISSING_METADATA_PROJECT_ID, ['project_id'], false],
     [CONFIG_MISSING_METADATA_ZONE, [], true],
     [CONFIG_MISSING_METADATA_VM_ID, [], true],
     [CONFIG_MISSING_METADATA_ALL, ['project_id'], false]
    ].each_with_index do |(config, missing_parts, is_valid_config), index|
      begin
        create_driver(config)
        assert_true is_valid_config, "Invalid config at index #{index} should "\
          'have raised an error.'
      rescue Fluent::ConfigError => error
        assert_false is_valid_config, "Valid config at index #{index} should "\
          "not have raised an error #{error}."
        assert error.message.include?('Unable to obtain metadata parameters:'),
               "Index #{index} failed."
        missing_parts.each do |part|
          assert error.message.include?(part), "Index #{index} failed."
        end
      end
    end
  end

  def test_configure_ignores_unknown_monitoring_type
    # Verify that driver creation succeeds when monitoring type is not
    # "prometheus" (in which case, we simply don't record metrics),
    # and that the counters are set to nil.
    setup_gce_metadata_stubs
    create_driver(CONFIG_UNKNOWN_MONITORING_TYPE)
    assert_nil(Prometheus::Client.registry.get(
                 :stackdriver_successful_requests_count))
    assert_nil(Prometheus::Client.registry.get(
                 :stackdriver_failed_requests_count))
    assert_nil(Prometheus::Client.registry.get(
                 :stackdriver_ingested_entries_count))
    assert_nil(Prometheus::Client.registry.get(
                 :stackdriver_dropped_entries_count))
    assert_nil(Prometheus::Client.registry.get(
                 :stackdriver_retried_entries_count))
  end

  def test_metadata_loading
    setup_gce_metadata_stubs
    d = create_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal COMPUTE_CONSTANTS[:resource_type], d.instance.resource.type
  end

  def test_managed_vm_metadata_loading
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    d = create_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal APPENGINE_CONSTANTS[:resource_type], d.instance.resource.type
    assert_equal MANAGED_VM_BACKEND_NAME,
                 d.instance.resource.labels['module_id']
    assert_equal MANAGED_VM_BACKEND_VERSION,
                 d.instance.resource.labels['version_id']
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    d = create_driver(NO_METADATA_SERVICE_CONFIG + CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal COMPUTE_CONSTANTS[:resource_type], d.instance.resource.type
  end

  def test_gce_used_when_detect_subservice_is_false
    setup_gce_metadata_stubs
    # This would cause the resource type to be container.googleapis.com if not
    # for the detect_subservice=false config.
    setup_k8s_metadata_stubs
    d = create_driver(NO_DETECT_SUBSERVICE_CONFIG)
    d.run
    assert_equal COMPUTE_CONSTANTS[:resource_type], d.instance.resource.type
  end

  def test_metadata_overrides
    {
      # In this case we are overriding all configured parameters so we should
      # see all "custom" values rather than the ones from the metadata server.
      CUSTOM_METADATA_CONFIG =>
        ['gce', CUSTOM_PROJECT_ID, CUSTOM_ZONE, CUSTOM_VM_ID],
      # Similar to above, but we are not overriding project_id in this config so
      # we should see the metadata value for project_id and "custom" otherwise.
      CONFIG_MISSING_METADATA_PROJECT_ID =>
        ['gce', PROJECT_ID, CUSTOM_ZONE, CUSTOM_VM_ID],
      CONFIG_EC2_PROJECT_ID =>
        ['ec2', EC2_PROJECT_ID, EC2_PREFIXED_ZONE, EC2_VM_ID],
      CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID =>
        ['ec2', EC2_PROJECT_ID, EC2_PREFIXED_ZONE, CUSTOM_VM_ID],
      CONFIG_EC2_PROJECT_ID_USE_REGION =>
        ['ec2', EC2_PROJECT_ID, EC2_PREFIXED_REGION, EC2_VM_ID]
    }.each_with_index do |(config, parts), index|
      send("setup_#{parts[0]}_metadata_stubs")
      d = create_driver(config)
      d.run
      assert_equal parts[1], d.instance.project_id, "Index #{index} failed."
      assert_equal parts[2], d.instance.zone, "Index #{index} failed."
      assert_equal parts[3], d.instance.vm_id, "Index #{index} failed."
    end
  end

  def test_ec2_metadata_requires_project_id
    setup_ec2_metadata_stubs
    exception_count = 0
    begin
      create_driver
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_project_id_from_credentials
    %w(gce ec2).each do |platform|
      send("setup_#{platform}_metadata_stubs")
      [IAM_CREDENTIALS, NEW_STYLE_CREDENTIALS, LEGACY_CREDENTIALS].each \
      do |creds|
        ENV[CREDENTIALS_PATH_ENV_VAR] = creds[:path]
        d = create_driver
        d.run
        assert_equal creds[:project_id], d.instance.project_id
      end
    end
  end

  def test_one_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_json_credentials
    setup_gce_metadata_stubs
    ENV[CREDENTIALS_PATH_ENV_VAR] = IAM_CREDENTIALS[:path]
    setup_logging_stubs do
      d = create_driver
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS.merge(
                            project_id: IAM_CREDENTIALS[:project_id]))
  end

  def test_invalid_json_credentials
    %w(gce_metadata ec2_metadata no_metadata_service).each do |platform|
      send("setup_#{platform}_stubs")
      exception_count = 0
      ENV[CREDENTIALS_PATH_ENV_VAR] = INVALID_CREDENTIALS[:path]
      begin
        create_driver
      rescue RuntimeError => error
        assert error.message.include? 'Unable to read the credential file'
        exception_count += 1
      end
      assert_equal 1, exception_count
    end
  end

  def test_unset_or_empty_credentials_path_env_var
    # An empty string should be treated as if it's not set.
    [nil, ''].each do |value|
      ENV[CREDENTIALS_PATH_ENV_VAR] = value
      setup_gce_metadata_stubs
      create_driver
      assert_nil ENV[CREDENTIALS_PATH_ENV_VAR]
    end
  end

  def test_one_log_custom_metadata
    # don't set up any metadata stubs, so the test will fail if we try to
    # fetch metadata (and explicitly check this as well).
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    ENV[CREDENTIALS_PATH_ENV_VAR] = IAM_CREDENTIALS[:path]
    setup_logging_stubs do
      d = create_driver(NO_METADATA_SERVICE_CONFIG + CUSTOM_METADATA_CONFIG)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, CUSTOM_PARAMS)
  end

  def test_one_log_ec2
    ENV[CREDENTIALS_PATH_ENV_VAR] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_logging_stubs do
      d = create_driver(CONFIG_EC2_PROJECT_ID)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, EC2_ZONE_PARAMS)
  end

  def test_one_log_ec2_region
    ENV[CREDENTIALS_PATH_ENV_VAR] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_logging_stubs do
      d = create_driver(CONFIG_EC2_PROJECT_ID_USE_REGION)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, EC2_REGION_PARAMS)
  end

  def test_structured_payload_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000,
             'some_null_field' => nil)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry, i|
      fields = entry['jsonPayload']
      assert_equal 4, fields.size, entry
      verify_default_log_entry_text(fields['msg'], i, entry)
      assert_equal 'test', fields['tag2'], entry
      assert_equal 5000, fields['data'], entry
      assert_nil fields['some_null_field'], entry
    end
  end

  def test_autoformat_enabled_with_stackdriver_trace_id_as_trace
    [
      APPLICATION_DEFAULT_CONFIG,
      ENABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG
    ].each do |config|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_logging_stubs do
          d = create_driver(config)
          d.emit(DEFAULT_TRACE_KEY => STACKDRIVER_TRACE_ID)
          d.run
          verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
            assert_equal FULL_STACKDRIVER_TRACE, entry['trace'],
                         'stackdriver trace id should be autoformatted ' \
                         'when autoformat_stackdriver_trace is enabled.'
          end
        end
      end
    end
  end

  def test_autoformat_disabled_with_stackdriver_trace_id_as_trace
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver(DISABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG)
      d.emit(DEFAULT_TRACE_KEY => STACKDRIVER_TRACE_ID)
      d.run
      verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
        assert_equal STACKDRIVER_TRACE_ID, entry['trace'],
                     'trace as stackdriver trace id should not be ' \
                     'autoformatted with config ' \
                     "#{DISABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG}."
      end
    end
  end

  def test_no_trace_when_trace_key_not_exists_with_any_autoformat_config
    [
      APPLICATION_DEFAULT_CONFIG,
      ENABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG,
      DISABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG
    ].each do |config|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_logging_stubs do
          d = create_driver(config)
          d.emit('msg' => log_entry(0))
          d.run
          verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
            assert_false entry.key?('trace'), entry
          end
        end
      end
    end
  end

  def test_non_stackdriver_trace_id_compliant_trace_with_any_autoformat_config
    configs = [
      APPLICATION_DEFAULT_CONFIG,
      ENABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG,
      DISABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG
    ]
    traces = [
      TRACE, # Full trace won't be modified.
      EMPTY_STRING,
      INVALID_SHORT_STACKDRIVER_TRACE_ID,
      INVALID_LONG_STACKDRIVER_TRACE_ID,
      INVALID_NON_HEX_STACKDRIVER_TRACE_ID,
      INVALID_TRACE_NO_TRACE_ID,
      INVALID_TRACE_NO_PROJECT_ID,
      INVALID_TRACE_WITH_SHORT_TRACE_ID,
      INVALID_TRACE_WITH_LONG_TRACE_ID,
      INVALID_TRACE_WITH_NON_HEX_TRACE_ID
    ]
    configs.product(traces).each do |config, trace|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_logging_stubs do
          d = create_driver(config)
          d.emit(DEFAULT_TRACE_KEY => trace)
          d.run
          verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
            assert_equal_with_default \
              entry['trace'], trace, '',
              'trace as non stackdriver trace id should not be ' \
              "autoformatted with config #{config}."
          end
        end
      end
    end
  end

  def test_structured_payload_malformatted_log
    setup_gce_metadata_stubs
    message = 'test message'
    setup_logging_stubs do
      d = create_driver
      d.emit(
        'int_key' => { 1 => message },
        'int_array_key' => { [1, 2, 3, 4] => message },
        'string_array_key' => { %w(a b c) => message },
        'hash_key' => { { 'some_key' => 'some_value' } => message },
        'mixed_key' => { { 'some_key' => %w(a b c) } => message },
        'symbol_key' => { some_symbol: message },
        'nil_key' => { nil => message }
      )
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 7, fields.size, entry
      assert_equal message, fields['int_key']['1'], entry
      assert_equal message, fields['int_array_key']['[1, 2, 3, 4]'], entry
      assert_equal message, fields['string_array_key']['["a", "b", "c"]'], entry
      assert_equal message, fields['hash_key']['{"some_key"=>"some_value"}'],
                   entry
      assert_equal message,
                   fields['mixed_key']['{"some_key"=>["a", "b", "c"]}'], entry
      assert_equal message, fields['symbol_key']['some_symbol'], entry
      assert_equal message, fields['nil_key'][''], entry
    end
  end

  def test_structured_payload_json_log_default_not_parsed_text
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG)
      d.emit('message' => 'notJSON ' + json_string)
      d.emit('message' => json_string)
      d.emit('message' => "  \r\n \t" + json_string)
      d.run
    end
    verify_log_entries(3, COMPUTE_PARAMS, 'textPayload') do
      # Only check for the existence of textPayload.
    end
  end

  def test_structured_payload_json_log_default_not_parsed_json
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG)
      %w(log msg).each do |field|
        d.emit(field => 'notJSON ' + json_string)
        d.emit(field => json_string)
        d.emit(field => "  \r\n \t" + json_string)
      end
      d.run
    end
    verify_log_entries(6, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert !fields.key?('tag2'), 'Did not expect tag2'
      assert !fields.key?('data'), 'Did not expect data'
      assert !fields.key?('some_null_field'), 'Did not expect some_null_field'
    end
  end

  def test_structured_payload_json_log_detect_json_not_parsed_text
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG)
      d.emit('message' => 'notJSON ' + json_string)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'textPayload') do
      # Only check for the existence of textPayload.
    end
  end

  def test_structured_payload_json_log_detect_json_not_parsed_json
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG)
      %w(log msg).each do |field|
        d.emit(field => 'notJSON ' + json_string)
      end
      d.run
    end
    verify_log_entries(2, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert !fields.key?('tag2'), 'Did not expect tag2'
      assert !fields.key?('data'), 'Did not expect data'
      assert !fields.key?('some_null_field'), 'Did not expect some_null_field'
    end
  end

  # TODO(qingling128): Fix the inconsistent behavior of 'message', 'log' and
  # 'msg' in the next major version 1.0.0.
  def test_structured_payload_json_log_detect_json_with_hash_input
    hash_value = {
      'msg' => 'test log entry 0',
      'tag2' => 'test',
      'data' => 5000,
      'some_null_field' => nil
    }
    [
      {
        config: APPLICATION_DEFAULT_CONFIG,
        field_name: 'log',
        expected_payload: 'jsonPayload'
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        field_name: 'msg',
        expected_payload: 'jsonPayload'
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        field_name: 'message',
        expected_payload: 'textPayload'
      },
      {
        config: DETECT_JSON_CONFIG,
        field_name: 'log',
        expected_payload: 'jsonPayload'
      },
      {
        config: DETECT_JSON_CONFIG,
        field_name: 'msg',
        expected_payload: 'jsonPayload'
      },
      {
        config: DETECT_JSON_CONFIG,
        field_name: 'message',
        expected_payload: 'textPayload'
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_logging_stubs do
          d = create_driver(test_params[:config])
          d.emit(test_params[:field_name] => hash_value)
          d.run
        end
        if test_params[:expected_payload] == 'textPayload'
          verify_log_entries(1, COMPUTE_PARAMS, 'textPayload') do |entry|
            text_payload = entry['textPayload']
            assert_equal '{"msg"=>"test log entry 0", "tag2"=>"test", ' \
                         '"data"=>5000, "some_null_field"=>nil}',
                         text_payload, entry
          end
        else
          verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
            json_payload = entry['jsonPayload']
            assert_equal 1, json_payload.size, entry
            fields = json_payload[test_params[:field_name]]
            assert_equal 4, fields.size, entry
            assert_equal 'test log entry 0', fields['msg'], entry
            assert_equal 'test', fields['tag2'], entry
            assert_equal 5000, fields['data'], entry
            assert_nil fields['some_null_field'], entry
          end
        end
      end
    end
  end

  def test_structured_payload_json_log_detect_json_parsed
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG)
      %w(message log msg).each do |field|
        d.emit(field => json_string)
        d.emit(field => "  \r\n \t" + json_string)
      end
      d.run
    end
    verify_log_entries(6, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 4, fields.size, entry
      assert_equal 'test log entry 0', fields['msg'], entry
      assert_equal 'test', fields['tag2'], entry
      assert_equal 5000, fields['data'], entry
      assert_nil fields['some_null_field'], entry
    end
  end

  def test_structured_payload_json_log_default_container_not_parsed
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('notJSON' + json_string))
      d.emit(container_log_entry_with_metadata(json_string))
      d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
      d.run
    end
    verify_log_entries(3, CONTAINER_FROM_METADATA_PARAMS, 'textPayload') do
      # Only check for the existence of textPayload.
    end
  end

  def test_structured_payload_json_log_detect_json_container_not_parsed
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('notJSON' + json_string))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS, 'textPayload') do
      # Only check for the existence of textPayload.
    end
  end

  def test_structured_payload_json_log_detect_json_container_parsed
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata(json_string))
      d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
      d.run
    end
    verify_log_entries(2, CONTAINER_FROM_METADATA_PARAMS, 'jsonPayload') \
      do |entry|
        fields = entry['jsonPayload']
        assert_equal 4, fields.size, entry
        assert_equal 'test log entry 0', fields['msg'], entry
        assert_equal 'test', fields['tag2'], entry
        assert_equal 5000, fields['data'], entry
        assert_nil fields['some_null_field'], entry
      end
  end

  # Verify that when the log has only one effective field (named 'log',
  # 'message', or 'msg') and the field is in JSON format, the field is parsed as
  # JSON and sent as jsonPayload.
  def test_detect_json_auto_triggered_with_one_field
    setup_gce_metadata_stubs
    json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                  '"data": 5000, "some_null_field": null}'
    PRESERVED_KEYS_TIMESTAMP_FIELDS.each do |timestamp_fields|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(DETECT_JSON_CONFIG)
        %w(message log msg).each do |field|
          d.emit(PRESERVED_KEYS_MAP.merge(
            field => json_string).merge(timestamp_fields))
        end
        d.run
      end
      expected_params = COMPUTE_PARAMS.merge(
        labels: COMPUTE_PARAMS[:labels].merge(LABELS_MESSAGE))
      verify_log_entries(3, expected_params, 'jsonPayload') do |entry|
        fields = entry['jsonPayload']
        assert_equal 4, fields.size, entry
        assert_equal 'test log entry 0', fields['msg'], entry
        assert_equal 'test', fields['tag2'], entry
        assert_equal 5000, fields['data'], entry
        assert_nil fields['some_null_field'], entry
      end
    end
  end

  # Verify that we drop the log entries when 'require_valid_tags' is true and
  # any non-string tags or tags with non-utf8 characters are detected.
  def test_reject_invalid_tags_with_require_valid_tags_true
    setup_gce_metadata_stubs
    INVALID_TAGS.keys.each do |tag|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(REQUIRE_VALID_TAGS_CONFIG, tag)
        d.emit('msg' => log_entry(0))
        d.run
      end
      verify_log_entries(0, COMPUTE_PARAMS, 'jsonPayload')
    end
  end

  # Verify that empty string container name should fail the kubernetes regex
  # match, thus the original tag is used as the log name.
  def test_handle_empty_container_name
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    container_name = ''
    # This tag will not match the kubernetes regex because it requires a
    # non-empty container name.
    tag = container_tag_with_container_name(container_name)
    setup_logging_stubs do
      d = create_driver(REQUIRE_VALID_TAGS_CONFIG, tag)
      d.emit(container_log_entry_with_metadata(log_entry(0), container_name))
      d.run
    end
    params = CONTAINER_FROM_METADATA_PARAMS.merge(
      resource: CONTAINER_FROM_METADATA_PARAMS[:resource].merge(
        labels: CONTAINER_FROM_METADATA_PARAMS[:resource][:labels].merge(
          'container_name' => container_name)),
      log_name: tag)
    verify_log_entries(1, params, 'textPayload')
  end

  # Verify that container names with non-utf8 characters should be rejected when
  # 'require_valid_tags' is true.
  def test_reject_non_utf8_container_name_with_require_valid_tags_true
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    non_utf8_tags = INVALID_TAGS.select do |tag, _|
      tag.is_a?(String) && !tag.empty?
    end
    non_utf8_tags.each do |container_name, encoded_name|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(REQUIRE_VALID_TAGS_CONFIG,
                          container_tag_with_container_name(container_name))
        d.emit(container_log_entry_with_metadata(log_entry(0), container_name))
        d.run
      end
      params = CONTAINER_FROM_METADATA_PARAMS.merge(
        labels: CONTAINER_FROM_METADATA_PARAMS[:labels].merge(
          "#{GKE_CONSTANTS[:service]}/container_name" =>
            URI.decode(encoded_name)),
        log_name: encoded_name)
      verify_log_entries(0, params, 'textPayload')
    end
  end

  # Verify that tags are properly encoded. When 'require_valid_tags' is true, we
  # only accept string tags with utf8 characters.
  def test_encode_tags_with_require_valid_tags_true
    setup_gce_metadata_stubs
    VALID_TAGS.each do |tag, encoded_tag|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(REQUIRE_VALID_TAGS_CONFIG, tag)
        d.emit('msg' => log_entry(0))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS.merge(log_name: encoded_tag),
                         'jsonPayload')
    end
  end

  # Verify that tags extracted from container names are properly encoded.
  def test_encode_tags_from_container_name_with_require_valid_tags_true
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    VALID_TAGS.each do |tag, encoded_tag|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(REQUIRE_VALID_TAGS_CONFIG,
                          container_tag_with_container_name(tag))
        d.emit(container_log_entry_with_metadata(log_entry(0), tag))
        d.run
      end
      params = CONTAINER_FROM_METADATA_PARAMS.merge(
        resource: CONTAINER_FROM_METADATA_PARAMS[:resource].merge(
          labels: CONTAINER_FROM_METADATA_PARAMS[:resource][:labels].merge(
            'container_name' => tag)),
        log_name: encoded_tag)
      verify_log_entries(1, params, 'textPayload')
    end
  end

  # Verify that tags are properly encoded and sanitized. When
  # 'require_valid_tags' is false, we try to convert any non-string tags to
  # strings, and replace non-utf8 characters with a replacement string.
  def test_sanitize_tags_with_require_valid_tags_false
    setup_gce_metadata_stubs
    ALL_TAGS.each do |tag, sanitized_tag|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(APPLICATION_DEFAULT_CONFIG, tag)
        d.emit('msg' => log_entry(0))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS.merge(log_name: sanitized_tag),
                         'jsonPayload')
    end
  end

  # Verify that tags extracted from container names are properly encoded and
  # sanitized.
  def test_sanitize_tags_from_container_name_with_require_valid_tags_false
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    # Log names are derived from container names for containers. And container
    # names are extracted from the tag based on a regex match pattern. As a
    # prerequisite, the tag should already be a string, thus we only test
    # non-empty string cases here.
    string_tags = ALL_TAGS.select { |tag, _| tag.is_a?(String) && !tag.empty? }
    string_tags.each do |container_name, encoded_container_name|
      # Container name in the label is sanitized but not encoded, while the log
      # name is encoded.
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(APPLICATION_DEFAULT_CONFIG,
                          container_tag_with_container_name(container_name))
        d.emit(container_log_entry_with_metadata(log_entry(0), container_name))
        d.run
      end
      params = CONTAINER_FROM_METADATA_PARAMS.merge(
        resource: CONTAINER_FROM_METADATA_PARAMS[:resource].merge(
          labels: CONTAINER_FROM_METADATA_PARAMS[:resource][:labels].merge(
            'container_name' => URI.decode(encoded_container_name))),
        log_name: encoded_container_name)
      verify_log_entries(1, params, 'textPayload')
    end
  end

  def test_configure_split_logs_by_tag
    setup_gce_metadata_stubs
    {
      APPLICATION_DEFAULT_CONFIG => false,
      ENABLE_SPLIT_LOGS_BY_TAG_CONFIG => true
    }.each do |(config, split_logs_by_tag)|
      d = create_driver(config)
      assert_equal split_logs_by_tag,
                   d.instance.instance_variable_get(:@split_logs_by_tag)
    end
  end

  def test_split_logs_by_tag
    setup_gce_metadata_stubs
    log_entry_count = 5
    dynamic_log_names = (0..log_entry_count - 1).map do |index|
      "projects/test-project-id/logs/tag#{index}"
    end
    [
      [APPLICATION_DEFAULT_CONFIG, 1, [''], dynamic_log_names],
      # [] returns nil for any index.
      [ENABLE_SPLIT_LOGS_BY_TAG_CONFIG, log_entry_count, dynamic_log_names, []]
    ].each do |(config, request_count, request_log_names, entry_log_names)|
      clear_metrics
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(config + ENABLE_PROMETHEUS_CONFIG, 'test', true)
        log_entry_count.times do |i|
          d.emit("tag#{i}", 'message' => log_entry(i))
        end
        d.run
      end
      @logs_sent.zip(request_log_names).each do |request, log_name|
        assert_equal log_name, request['logName']
      end
      verify_log_entries(log_entry_count, COMPUTE_PARAMS_NO_LOG_NAME,
                         'textPayload') do |entry, entry_index|
        verify_default_log_entry_text(entry['textPayload'], entry_index,
                                      entry)
        assert_equal entry_log_names[entry_index], entry['logName']
      end
      # Verify the number of requests is different based on whether the
      # 'split_logs_by_tag' flag is enabled.
      assert_prometheus_metric_value(:stackdriver_successful_requests_count,
                                     request_count, :aggregate)
      assert_prometheus_metric_value(:stackdriver_ingested_entries_count,
                                     log_entry_count, :aggregate)
    end
  end

  def test_compute_timestamp
    setup_gce_metadata_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)

    compute_timestamp = lambda do |driver, record, time|
      driver.instance.send(:compute_timestamp, record, time)
    end

    current_time = Time.new(2019, 12, 29, 10, 23, 35, '-08:00')
    one_day_later = current_time.to_datetime.next_day.to_time
    just_under_one_day_later = one_day_later - 1
    next_year = Time.mktime(current_time.year + 1)
    one_second_before_next_year = next_year - 1
    one_second_into_next_year = next_year + 1
    one_day_into_next_year = next_year.to_datetime.next_day.to_time

    [
      Time.at(123_456.789),
      Time.at(0),
      current_time,
      just_under_one_day_later,
      one_second_before_next_year,
      next_year,
      one_second_into_next_year,
      one_day_into_next_year
    ].each do |ts|
      # Use record collection time.
      ts_secs, ts_nanos, actual_ts = compute_timestamp[d, {
        'message' => ''
      }, ts.to_f]
      assert_timestamp_matches ts, ts_secs, ts_nanos, actual_ts.iso8601

      # Use the (deprecated) timeNanos key.
      ts_secs, ts_nanos, actual_ts = compute_timestamp[d, {
        'message' => '',
        'timeNanos' => ts.tv_sec * 1_000_000_000 + ts.tv_nsec
      }, 1.0]
      assert_timestamp_matches ts, ts_secs, ts_nanos, actual_ts.iso8601

      # Use the structured timestamp key.
      ts_secs, ts_nanos, actual_ts = compute_timestamp[d, {
        'message' => '',
        'timestamp' => { 'seconds' => ts.tv_sec, 'nanos' => ts.tv_nsec }
      }, 1.0]
      assert_timestamp_matches ts, ts_secs, ts_nanos, actual_ts.iso8601

      # Use the timestampSeconds/timestampNanos keys.
      ts_secs, ts_nanos, actual_ts = compute_timestamp[d, {
        'message' => '',
        'timestampSeconds' => ts.tv_sec,
        'timestampNanos' => ts.tv_nsec
      }, 1.0]
      assert_timestamp_matches ts, ts_secs, ts_nanos, actual_ts.iso8601

      # Use the string timestampSeconds/timestampNanos keys.
      ts_secs, ts_nanos, actual_ts = compute_timestamp[d, {
        'message' => '',
        'timestampSeconds' => ts.tv_sec.to_s,
        'timestampNanos' => ts.tv_nsec.to_s
      }, 1.0]
      assert_timestamp_matches ts, ts_secs, ts_nanos, actual_ts.iso8601
    end
  end

  def test_adjust_timestamp
    setup_gce_metadata_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)

    adjust_timestamp_if_invalid = lambda do |driver, timestamp, current_time|
      driver.instance.send(:adjust_timestamp_if_invalid, timestamp,
                           current_time)
    end

    december_29 = Time.new(2019, 12, 29, 10, 23, 35, '-08:00')
    december_31 = Time.new(2019, 12, 31, 10, 23, 35, '-08:00')
    january_1 = Time.new(2020, 1, 1, 10, 23, 35, '-08:00')

    {
      # December 29, 2019 (normal operation).
      december_29 => begin
        one_day_later = Time.new(2019, 12, 30, 10, 23, 35, '-08:00')
        one_day_a_year_earlier = Time.new(2018, 12, 30, 10, 23, 35, '-08:00')
        just_under_one_day_later = Time.new(2019, 12, 30, 10, 23, 34, '-08:00')
        next_year = Time.new(2020, 1, 1, 0, 0, 0, '-08:00')
        one_second_before_next_year =
          Time.new(2019, 12, 31, 11, 59, 59, '-08:00')
        one_second_before_this_year =
          Time.new(2018, 12, 31, 11, 59, 59, '-08:00')
        one_second_into_next_year = Time.new(2020, 1, 1, 0, 0, 1, '-08:00')
        one_day_into_next_year = Time.new(2020, 1, 2, 0, 0, 0, '-08:00')
        {
          Time.at(123_456.789) => Time.at(123_456.789),
          Time.at(0) => Time.at(0),
          december_29 => december_29,
          one_day_later => one_day_a_year_earlier,
          just_under_one_day_later => just_under_one_day_later,
          one_second_before_next_year => one_second_before_this_year,
          next_year => Time.at(0),
          one_second_into_next_year => Time.at(0),
          one_day_into_next_year => Time.at(0)
        }
      end,
      # January 1, 2020 (normal operation).
      january_1 => begin
        one_day_later = Time.new(2020, 1, 2, 10, 23, 35, '-08:00')
        one_day_a_year_earlier = Time.new(2019, 1, 2, 10, 23, 35, '-08:00')
        just_under_one_day_later = Time.new(2020, 1, 2, 10, 23, 34, '-08:00')
        next_year = Time.new(2021, 1, 1, 0, 0, 0, '-08:00')
        one_second_before_next_year =
          Time.new(2020, 12, 31, 11, 59, 59, '-08:00')
        one_second_before_this_year =
          Time.new(2019, 12, 31, 11, 59, 59, '-08:00')
        one_second_into_next_year = Time.new(2021, 1, 1, 0, 0, 1, '-08:00')
        one_day_into_next_year = Time.new(2021, 1, 2, 0, 0, 0, '-08:00')
        {
          Time.at(123_456.789) => Time.at(123_456.789),
          Time.at(0) => Time.at(0),
          january_1 => january_1,
          one_day_later => one_day_a_year_earlier,
          just_under_one_day_later => just_under_one_day_later,
          one_second_before_next_year => one_second_before_this_year,
          next_year => Time.at(0),
          one_second_into_next_year => Time.at(0),
          one_day_into_next_year => Time.at(0)
        }
      end,
      # December 31, 2019 (next day overlaps new year).
      december_31 => begin
        one_day_later = Time.new(2020, 1, 1, 10, 23, 35, '-08:00')
        just_under_one_day_later = Time.new(2020, 1, 1, 10, 23, 34, '-08:00')
        next_year = Time.new(2020, 1, 1, 0, 0, 0, '-08:00')
        one_second_before_next_year =
          Time.new(2019, 12, 31, 11, 59, 59, '-08:00')
        one_second_into_next_year = Time.new(2020, 1, 1, 0, 0, 1, '-08:00')
        one_day_into_next_year = Time.new(2020, 1, 2, 0, 0, 0, '-08:00')
        {
          Time.at(123_456.789) => Time.at(123_456.789),
          Time.at(0) => Time.at(0),
          december_31 => december_31,
          one_day_later => Time.at(0), # Falls into the next year.
          just_under_one_day_later => just_under_one_day_later,
          one_second_before_next_year => one_second_before_next_year,
          next_year => next_year,
          one_second_into_next_year => one_second_into_next_year,
          one_day_into_next_year => Time.at(0)
        }
      end
    }.each do |current_time, timestamps|
      timestamps.each do |ts, expected_ts|
        ts_secs, ts_nanos = adjust_timestamp_if_invalid[d, ts, current_time]
        adjusted_ts = Time.at(ts_secs, ts_nanos / 1_000.0)
        assert_timestamp_matches expected_ts, ts_secs, ts_nanos,
                                 adjusted_ts.iso8601
      end
    end
  end

  def test_log_timestamps
    setup_gce_metadata_stubs
    current_time = Time.now
    {
      # Verify that timestamps make it through.
      Time.at(123_456.789) => Time.at(123_456.789),
      Time.at(0) => Time.at(0),
      current_time => current_time
    }.each do |ts, expected_ts|
      emit_index = 0
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(APPLICATION_DEFAULT_CONFIG)
        # Test the "native" fluentd timestamp as well as our nanosecond tags.
        d.emit({ 'message' => log_entry(emit_index) }, ts.to_f)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timeNanos' => ts.tv_sec * 1_000_000_000 + ts.tv_nsec)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timestamp' => { 'seconds' => ts.tv_sec,
                                'nanos' => ts.tv_nsec })
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timestampSeconds' => ts.tv_sec,
               'timestampNanos' => ts.tv_nsec)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timestampSeconds' => ts.tv_sec.to_s,
               'timestampNanos' => ts.tv_nsec.to_s)
        emit_index += 1
        d.run
        verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry, i|
          verify_default_log_entry_text(entry['textPayload'], i, entry)
          actual_timestamp = timestamp_parse(entry['timestamp'])
          assert_timestamp_matches expected_ts, actual_timestamp['seconds'],
                                   actual_timestamp['nanos'], entry
        end
      end
    end
  end

  def test_malformed_timestamp_field
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      # if timestamp is not a hash it is passed through to the json payload.
      d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 2, fields.size, entry
      assert_equal 'not-a-hash', fields['timestamp'], entry
    end
  end

  # Make parse_severity public so we can test it.
  class Fluent::GoogleCloudOutput # rubocop:disable Style/ClassAndModuleChildren
    public :parse_severity
  end

  def test_label_map_without_field_present
    setup_gce_metadata_stubs
    setup_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver(config)
      d.emit('message' => log_entry(0))
      d.run
      # No additional labels should be present
    end
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_label_map_with_field_present
    setup_gce_metadata_stubs
    setup_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver(config)
      d.emit('message' => log_entry(0), 'label_field' => 'label_value')
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = 'label_value'
    verify_log_entries(1, params)
  end

  def test_label_map_with_numeric_field
    setup_gce_metadata_stubs
    setup_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver(config)
      d.emit('message' => log_entry(0), 'label_field' => 123_456_789)
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '123456789'
    verify_log_entries(1, params)
  end

  def test_label_map_with_hash_field
    setup_gce_metadata_stubs
    setup_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver(config)
      # I'm not sure this actually makes sense for a user to do, but make
      # sure that it works if they try it.
      d.emit('message' => log_entry(0),
             'label_field' => { 'k1' => 10, 'k2' => 'val' })
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '{"k1"=>10, "k2"=>"val"}'
    verify_log_entries(1, params)
  end

  def test_label_map_with_multiple_fields
    setup_gce_metadata_stubs
    setup_logging_stubs do
      config = %(
        label_map {
          "label1": "sent_label_1",
          "label_number_two": "foo.googleapis.com/bar",
          "label3": "label3"
        }
      )
      d = create_driver(config)
      # not_a_label passes through to the json payload
      d.emit('message' => log_entry(0),
             'label1' => 'value1',
             'label_number_two' => 'value2',
             'not_a_label' => 'value4',
             'label3' => 'value3')
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed labels.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label_1'] = 'value1'
    params[:labels]['foo.googleapis.com/bar'] = 'value2'
    params[:labels]['label3'] = 'value3'
    verify_log_entries(1, params, 'jsonPayload') do |entry, i|
      fields = entry['jsonPayload']
      assert_equal 2, fields.size, entry
      verify_default_log_entry_text(fields['message'], i, entry)
      assert_equal 'value4', fields['not_a_label'], entry
    end
  end

  def test_multiple_logs
    setup_gce_metadata_stubs
    # Only test a few values because otherwise the test can take minutes.
    [2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs do
        d = create_driver
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
      end
      verify_log_entries(n, COMPUTE_PARAMS)
    end
  end

  def test_malformed_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      # if the entry is not a hash, the plugin should silently drop it.
      d.emit('a string is not a valid message')
      d.run
    end
    assert @logs_sent.empty?
  end

  def test_one_managed_vm_log
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, VMENGINE_PARAMS)
  end

  def test_multiple_managed_vm_logs
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs do
        d = create_driver
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
      end
      verify_log_entries(n, VMENGINE_PARAMS)
    end
  end

  # Test container logs when metadata is extracted from the 'kubernetes' field
  # in the log record.
  def test_container_logs_metadata_from_record
    verify_container_logs(method(:container_log_entry_with_metadata),
                          CONTAINER_FROM_METADATA_PARAMS)
  end

  # Test container logs when metadata is extracted from the tag.
  def test_container_logs_metadata_from_tag
    verify_container_logs(method(:container_log_entry),
                          CONTAINER_FROM_TAG_PARAMS)
  end

  def test_one_container_log_from_tag_stderr
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0), 'stderr'))
      d.run
    end
    expected_params = CONTAINER_FROM_TAG_PARAMS.merge(
      labels: { "#{GKE_CONSTANTS[:service]}/stream" => 'stderr' }
    ) { |_, oldval, newval| oldval.merge(newval) }
    verify_log_entries(1, expected_params) do |entry, i|
      verify_default_log_entry_text(entry['textPayload'], i, entry)
      actual_timestamp = timestamp_parse(entry['timestamp'])
      assert_equal K8S_SECONDS_EPOCH, actual_timestamp['seconds'], entry
      assert_equal K8S_NANOS, actual_timestamp['nanos'], entry
      assert_equal 'ERROR', entry['severity'], entry
    end
  end

  def test_json_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                               '"tag2": "test", "data": ' \
                                               '5000, "severity": "WARNING"}'))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS,
                       'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', fields['msg'], entry
      assert_equal 'test', fields['tag2'], entry
      assert_equal 5000, fields['data'], entry
      actual_timestamp = timestamp_parse(entry['timestamp'])
      assert_equal K8S_SECONDS_EPOCH, actual_timestamp['seconds'], entry
      assert_equal K8S_NANOS, actual_timestamp['nanos'], entry
      assert_equal 'WARNING', entry['severity'], entry
    end
  end

  def test_json_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    setup_logging_stubs do
      d = create_driver(DETECT_JSON_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                                 '"tag2": "test", "data": 5000, ' \
                                 '"severity": "W"}'))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS,
                       'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', fields['msg'], entry
      assert_equal 'test', fields['tag2'], entry
      assert_equal 5000, fields['data'], entry
      actual_timestamp = timestamp_parse(entry['timestamp'])
      assert_equal K8S_SECONDS_EPOCH, actual_timestamp['seconds'], entry
      assert_equal K8S_NANOS, actual_timestamp['nanos'], entry
      assert_equal 'WARNING', entry['severity'], entry
    end
  end

  def test_dataproc_log
    setup_gce_metadata_stubs
    setup_dataproc_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(dataproc_log_entry('test message'))
      d.run
    end
    verify_log_entries(1, DATAPROC_PARAMS, 'jsonPayload')
  end

  def test_cloud_ml_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver(CONFIG_ML, ML_TAG)
      d.emit(ml_log_entry(0))
      d.run
    end
    verify_log_entries(1, ML_PARAMS)
  end

  def test_cloud_dataflow_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver(CONFIG_DATAFLOW, DATAFLOW_TAG)
      d.emit(dataflow_log_entry(0))
      d.run
    end
    verify_log_entries(1, DATAFLOW_PARAMS)
  end

  # Verify the subfields extraction of LogEntry fields.

  def test_log_entry_http_request_field_from_record
    verify_subfields_from_record(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_labels_field_from_record
    verify_subfields_from_record(DEFAULT_LABELS_KEY, false)
  end

  def test_log_entry_operation_field_from_record
    verify_subfields_from_record(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_source_location_field_from_record
    verify_subfields_from_record(DEFAULT_SOURCE_LOCATION_KEY)
  end

  # Verify the subfields extraction of LogEntry fields when there are other
  # fields.

  def test_log_entry_http_request_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_HTTP_REQUEST_KEY)
  end

  # We don't need a test like 'test_log_entry_labels_field_partial_from_record'
  # because labels are free range strings. Everything in the labels field should
  # be in the resulting logEntry->labels field. There is no need to check
  # partial transformation (aka, some 'labels' fields are extracted, while
  # others are left as it is).

  def test_log_entry_operation_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_source_location_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_SOURCE_LOCATION_KEY)
  end

  # Verify the subfields extraction of LogEntry fields when they are not hashes.

  def test_log_entry_http_request_field_when_not_hash
    # TODO(qingling128) On the next major after 0.7.4, make all logEntry
    # subfields behave the same way: if the field is not in the correct format,
    # log an error in the Fluentd log and remove this field from payload. This
    # is the preferred behavior per PM decision.
    verify_subfields_untouched_when_not_hash(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_labels_field_when_not_hash
    verify_subfields_removed_when_not_hash(DEFAULT_LABELS_KEY)
  end

  def test_log_entry_operation_field_when_not_hash
    # TODO(qingling128) On the next major after 0.7.4, make all logEntry
    # subfields behave the same way: if the field is not in the correct format,
    # log an error in the Fluentd log and remove this field from payload. This
    # is the preferred behavior per PM decision.
    verify_subfields_untouched_when_not_hash(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_source_location_field_when_not_hash
    # TODO(qingling128) On the next major after 0.7.4, make all logEntry
    # subfields behave the same way: if the field is not in the correct format,
    # log an error in the Fluentd log and remove this field from payload. This
    # is the preferred behavior per PM decision.
    verify_subfields_untouched_when_not_hash(DEFAULT_SOURCE_LOCATION_KEY)
  end

  # Verify the subfields extraction of LogEntry fields when they are nil.

  def test_log_entry_http_request_field_when_nil
    verify_subfields_when_nil(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_labels_field_when_nil
    verify_subfields_when_nil(DEFAULT_LABELS_KEY)
  end

  def test_log_entry_operation_field_when_nil
    verify_subfields_when_nil(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_source_location_field_when_nil
    verify_subfields_when_nil(DEFAULT_SOURCE_LOCATION_KEY)
  end

  def test_http_request_from_record_with_referer_nil_or_absent
    setup_gce_metadata_stubs
    [
      http_request_message_with_nil_referer,
      http_request_message_with_absent_referer
    ].each do |input|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver
        d.emit('httpRequest' => input)
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal http_request_message_with_absent_referer,
                     entry['httpRequest'], entry
        assert_nil entry['jsonPayload']['httpRequest'], entry
      end
    end
  end

  def test_http_request_with_latency
    setup_gce_metadata_stubs
    latency_conversion.each do |input, expected|
      setup_logging_stubs do
        d = create_driver
        @logs_sent = []
        d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE.merge('latency' => expected),
                     entry['httpRequest'], entry
        assert_nil entry['jsonPayload']['httpRequest'], entry
      end
    end
  end

  # Skip setting latency when the field is null or has invalid format.
  def test_http_request_skip_setting_latency
    setup_gce_metadata_stubs
    [
      '', ' ', nil, 'null', '123', '1.23 seconds',
      ' 123 s econds ', '1min', 'abc&^!$*('
    ].each do |input|
      setup_logging_stubs do
        d = create_driver
        @logs_sent = []
        d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
        assert_nil entry['jsonPayload']['httpRequest'], entry
      end
    end
  end

  # Verify the default and customization of LogEntry field extraction key.

  def test_log_entry_insert_id_field
    verify_field_key('insertId',
                     default_key: DEFAULT_INSERT_ID_KEY,
                     custom_key: 'custom_insert_id_key',
                     custom_key_config: CONFIG_CUSTOM_INSERT_ID_KEY_SPECIFIED,
                     sample_value: INSERT_ID)
  end

  def test_log_entry_labels_field
    verify_field_key('labels',
                     default_key: DEFAULT_LABELS_KEY,
                     custom_key: 'custom_labels_key',
                     custom_key_config: CONFIG_CUSTOM_LABELS_KEY_SPECIFIED,
                     sample_value: COMPUTE_PARAMS[:labels].merge(
                       LABELS_MESSAGE),
                     default_value: COMPUTE_PARAMS[:labels])
  end

  def test_log_entry_operation_field
    verify_field_key('operation',
                     default_key: DEFAULT_OPERATION_KEY,
                     custom_key: 'custom_operation_key',
                     custom_key_config: CONFIG_CUSTOM_OPERATION_KEY_SPECIFIED,
                     sample_value: OPERATION_MESSAGE)
  end

  def test_log_entry_source_location_field
    verify_field_key('sourceLocation',
                     default_key: DEFAULT_SOURCE_LOCATION_KEY,
                     custom_key: 'custom_source_location_key',
                     custom_key_config: \
                       CONFIG_CUSTOM_SOURCE_LOCATION_KEY_SPECIFIED,
                     sample_value: SOURCE_LOCATION_MESSAGE)
  end

  def test_log_entry_span_id_field
    verify_field_key('spanId',
                     default_key: DEFAULT_SPAN_ID_KEY,
                     custom_key: 'custom_span_id_key',
                     custom_key_config: CONFIG_CUSTOM_SPAN_ID_KEY_SPECIFIED,
                     sample_value: SPAN_ID)
  end

  def test_log_entry_trace_field
    verify_field_key('trace',
                     default_key: DEFAULT_TRACE_KEY,
                     custom_key: 'custom_trace_key',
                     custom_key_config: CONFIG_CUSTOM_TRACE_KEY_SPECIFIED,
                     sample_value: TRACE)
  end

  def test_log_entry_trace_sampled_field
    verify_field_key('traceSampled',
                     default_key: DEFAULT_TRACE_SAMPLED_KEY,
                     custom_key: 'custom_trace_sampled_key',
                     custom_key_config:
                       CONFIG_CUSTOM_TRACE_SAMPLED_KEY_SPECIFIED,
                     sample_value: TRACE_SAMPLED)
  end

  # Verify the cascading JSON detection of LogEntry fields.

  def test_cascading_json_detection_with_log_entry_insert_id_field
    verify_cascading_json_detection_with_log_entry_fields(
      'insertId', DEFAULT_INSERT_ID_KEY,
      root_level_value: INSERT_ID,
      nested_level_value: INSERT_ID2)
  end

  def test_cascading_json_detection_with_log_entry_labels_field
    verify_cascading_json_detection_with_log_entry_fields(
      'labels', DEFAULT_LABELS_KEY,
      root_level_value: LABELS_MESSAGE,
      nested_level_value: LABELS_MESSAGE2,
      expected_value_from_root: COMPUTE_PARAMS[:labels].merge(LABELS_MESSAGE),
      expected_value_from_nested: COMPUTE_PARAMS[:labels].merge(
        LABELS_MESSAGE2))
  end

  def test_cascading_json_detection_with_log_entry_operation_field
    verify_cascading_json_detection_with_log_entry_fields(
      'operation', DEFAULT_OPERATION_KEY,
      root_level_value: OPERATION_MESSAGE,
      nested_level_value: OPERATION_MESSAGE2,
      expected_value_from_nested: expected_operation_message2)
  end

  def test_cascading_json_detection_with_log_entry_source_location_field
    verify_cascading_json_detection_with_log_entry_fields(
      'sourceLocation', DEFAULT_SOURCE_LOCATION_KEY,
      root_level_value: SOURCE_LOCATION_MESSAGE,
      nested_level_value: SOURCE_LOCATION_MESSAGE2)
  end

  def test_cascading_json_detection_with_log_entry_span_id_field
    verify_cascading_json_detection_with_log_entry_fields(
      'spanId', DEFAULT_SPAN_ID_KEY,
      root_level_value: SPAN_ID,
      nested_level_value: SPAN_ID2)
  end

  def test_cascading_json_detection_with_log_entry_trace_field
    verify_cascading_json_detection_with_log_entry_fields(
      'trace', DEFAULT_TRACE_KEY,
      root_level_value: TRACE,
      nested_level_value: TRACE2)
  end

  def test_cascading_json_detection_with_log_entry_trace_sampled_field
    verify_cascading_json_detection_with_log_entry_fields(
      'traceSampled', DEFAULT_TRACE_SAMPLED_KEY,
      root_level_value: TRACE_SAMPLED,
      nested_level_value: TRACE_SAMPLED2,
      default_value_from_root: false,
      default_value_from_nested: false)
  end

  # Verify that labels present in multiple inputs respect the expected priority
  # order:
  # 1. Labels from the field "logging.googleapis.com/labels" in payload.
  # 2. Labels from the config "label_map".
  # 3. Labels from the config "labels".
  def test_labels_order
    [
      # Labels from the config "labels".
      {
        config: CONFIG_LABELS,
        emitted_log: {},
        expected_labels: LABELS_FROM_LABELS_CONFIG
      },
      # Labels from the config "label_map".
      {
        config: CONFIG_LABEL_MAP,
        emitted_log: PAYLOAD_FOR_LABEL_MAP,
        expected_labels: LABELS_FROM_LABEL_MAP_CONFIG
      },
      # Labels from the field "logging.googleapis.com/labels" in payload.
      {
        config: APPLICATION_DEFAULT_CONFIG,
        emitted_log: { DEFAULT_LABELS_KEY => LABELS_MESSAGE },
        expected_labels: LABELS_MESSAGE
      },
      # All three types of labels that do not conflict.
      {
        config: CONFIG_LABLES_AND_LABLE_MAP,
        emitted_log: PAYLOAD_FOR_LABEL_MAP.merge(
          DEFAULT_LABELS_KEY => LABELS_MESSAGE),
        expected_labels: LABELS_MESSAGE.merge(LABELS_FROM_LABELS_CONFIG).merge(
          LABELS_FROM_LABEL_MAP_CONFIG)
      },
      # labels from the config "labels" and "label_map" conflict.
      {
        config: CONFIG_LABLES_AND_LABLE_MAP_CONFLICTING,
        emitted_log: PAYLOAD_FOR_LABEL_MAP_CONFLICTING,
        expected_labels: LABELS_FROM_LABEL_MAP_CONFIG_CONFLICTING
      },
      # labels from the config "labels" and labels from the field
      # "logging.googleapis.com/labels" in payload conflict.
      {
        config: CONFIG_LABELS_CONFLICTING,
        emitted_log: { DEFAULT_LABELS_KEY => LABELS_FROM_PAYLOAD_CONFLICTING },
        expected_labels: LABELS_FROM_PAYLOAD_CONFLICTING
      },
      # labels from the config "label_map" and labels from the field
      # "logging.googleapis.com/labels" in payload conflict.
      {
        config: CONFIG_LABEL_MAP_CONFLICTING,
        emitted_log: PAYLOAD_FOR_LABEL_MAP_CONFLICTING.merge(
          DEFAULT_LABELS_KEY => LABELS_FROM_PAYLOAD_CONFLICTING),
        expected_labels: LABELS_FROM_PAYLOAD_CONFLICTING
      },
      # All three types of labels conflict.
      {
        config: CONFIG_LABLES_AND_LABLE_MAP_CONFLICTING,
        emitted_log: PAYLOAD_FOR_LABEL_MAP_CONFLICTING.merge(
          DEFAULT_LABELS_KEY => LABELS_FROM_PAYLOAD_CONFLICTING),
        expected_labels: LABELS_FROM_PAYLOAD_CONFLICTING
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_logging_stubs do
          d = create_driver(test_params[:config])
          d.emit({ 'message' => log_entry(0) }.merge(test_params[:emitted_log]))
          d.run
        end
        expected_params = COMPUTE_PARAMS.merge(
          labels: COMPUTE_PARAMS[:labels].merge(test_params[:expected_labels]))
        verify_log_entries(1, expected_params)
      end
    end
  end

  # Test k8s_container monitored resource.
  def test_k8s_container_monitored_resource
    [
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_FALLBACK
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_FALLBACK
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      },
      {
        config: CUSTOM_K8S_CONFIG,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_CUSTOM
      },
      {
        config: EMPTY_K8S_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config], CONTAINER_TAG)
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params],
                           'jsonPayload') do |entry|
          fields = entry['jsonPayload']
          assert_equal 2, fields.size, entry
          assert_equal 'test log entry 0', fields['log'], entry
          assert_equal K8S_STREAM, fields['stream'], entry
        end
      end
    end
  end

  def test_k8s_container_monitored_resource_invalid_local_resource_id
    [
      # When local_resource_id is not present or does not match k8s regexes.
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(
          log_entry(0)).reject { |k, _| k == LOCAL_RESOURCE_ID_KEY },
        expected_params: CONTAINER_FROM_TAG_PARAMS
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(
          log_entry(0),
          local_resource_id: RANDOM_LOCAL_RESOURCE_ID),
        expected_params: CONTAINER_FROM_TAG_PARAMS
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config], CONTAINER_TAG)
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params]) do |entry|
          assert_equal 'test log entry 0', entry['textPayload'], entry
        end
      end
    end
  end

  # Test k8s_pod monitored resource.
  def test_k8s_pod_monitored_resource
    [
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_pod_log_entry(log_entry(0)),
        expected_params: K8S_POD_PARAMS_FROM_LOCAL
      },
      {
        config: CUSTOM_K8S_CONFIG,
        setup_k8s_stub: false,
        log_entry: k8s_pod_log_entry(log_entry(0)),
        expected_params: K8S_POD_PARAMS_CUSTOM
      },
      {
        config: EMPTY_K8S_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_pod_log_entry(log_entry(0)),
        expected_params: K8S_POD_PARAMS_FROM_LOCAL
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config])
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params],
                           'jsonPayload') do |entry|
          fields = entry['jsonPayload']
          assert_equal 2, fields.size, entry
          assert_equal 'test log entry 0', fields['log'], entry
          assert_equal K8S_STREAM, fields['stream'], entry
        end
      end
    end
  end

  # Test k8s_node monitored resource.
  def test_k8s_node_monitored_resource
    [
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_FROM_LOCAL
      },
      {
        config: CUSTOM_K8S_CONFIG,
        setup_k8s_stub: false,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_CUSTOM
      },
      {
        config: EMPTY_K8S_CONFIG,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_FROM_LOCAL
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config])
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params],
                           'jsonPayload') do |entry|
          fields = entry['jsonPayload']
          assert_equal 2, fields.size, entry
          assert_equal 'test log entry 0', fields['log'], entry
          assert_equal K8S_STREAM, fields['stream'], entry
        end
      end
    end
  end

  def test_uptime_metric
    setup_gce_metadata_stubs
    [
      [ENABLE_PROMETHEUS_CONFIG, method(:assert_prometheus_metric_value)],
      [ENABLE_OPENCENSUS_CONFIG, method(:assert_opencensus_metric_value)]
    ].each do |config, assert_metric_value|
      clear_metrics
      start_time = Time.now.to_i
      d = create_driver(config)
      d.run
      begin
        # Retry to protect from time races.
        retries ||= 0
        expected = Time.now.to_i - start_time
        d.instance.update_uptime
        assert_metric_value.call(
          :uptime, expected, version: Fluent::GoogleCloudOutput.version_string)
      rescue Test::Unit::AssertionFailedError
        retry if (retries += 1) < 3
      end
      assert_not_equal 3, retries
    end
  end

  private

  def stub_metadata_request(metadata_path, response_body)
    stub_request(:get, 'http://169.254.169.254/computeMetadata/v1/' +
                 metadata_path)
      .to_return(body: response_body, status: 200,
                 headers: { 'Content-Length' => response_body.length })
  end

  def setup_no_metadata_service_stubs
    # Simulate a machine with no metadata service present
    stub_request(:any, %r{http://169.254.169.254/.*})
      .to_raise(Errno::EHOSTUNREACH)
  end

  def setup_gce_metadata_stubs
    # Stub the root, used for platform detection by the plugin and 'googleauth'.
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Metadata-Flavor' => 'Google' })

    # Create stubs for all the GCE metadata lookups the agent needs to make.
    stub_metadata_request('project/project-id', PROJECT_ID)
    stub_metadata_request('instance/zone', FULLY_QUALIFIED_ZONE)
    stub_metadata_request('instance/id', VM_ID)
    stub_metadata_request('instance/attributes/',
                          "attribute1\nattribute2\nattribute3")

    # Used by 'googleauth' to fetch the default service account credentials.
    stub_request(:get, 'http://169.254.169.254/computeMetadata/v1/' \
                 'instance/service-accounts/default/token')
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })
  end

  def setup_ec2_metadata_stubs
    # Stub the root, used for platform detection.
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Server' => 'EC2ws' })

    # Stub the identity document lookup made by the agent.
    stub_request(:get, 'http://169.254.169.254/latest/dynamic/' \
                 'instance-identity/document')
      .to_return(body: EC2_IDENTITY_DOCUMENT, status: 200,
                 headers: { 'Content-Length' => EC2_IDENTITY_DOCUMENT.length })
  end

  def setup_auth_stubs
    # Used when loading credentials from a JSON file.
    stub_request(:post, 'https://www.googleapis.com/oauth2/v4/token')
      .with(body: hash_including(grant_type: AUTH_GRANT_TYPE))
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })

    stub_request(:post, 'https://www.googleapis.com/oauth2/v4/token')
      .with(body: hash_including(grant_type: 'refresh_token'))
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })
  end

  def setup_managed_vm_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\ngae_backend_name\ngae_backend_version\nlast_attribute")
    stub_metadata_request('instance/attributes/gae_backend_name',
                          MANAGED_VM_BACKEND_NAME)
    stub_metadata_request('instance/attributes/gae_backend_version',
                          MANAGED_VM_BACKEND_VERSION)
  end

  def setup_k8s_metadata_stubs(should_respond = true)
    if should_respond
      stub_metadata_request(
        'instance/attributes/',
        "attribute1\ncluster-location\ncluster-name\nlast_attribute")
      stub_metadata_request('instance/attributes/cluster-location',
                            K8S_LOCATION2)
      stub_metadata_request('instance/attributes/cluster-name',
                            K8S_CLUSTER_NAME)
    else
      ['cluster-location', 'cluster-name'].each do |metadata_name|
        stub_request(:get, %r{.*instance/attributes/#{metadata_name}.*})
          .to_return(status: 404,
                     body: 'The requested URL /computeMetadata/v1/instance/' \
                           "attributes/#{metadata_name} was not found on this" \
                           ' server.')
      end
    end
  end

  def setup_dataproc_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\ndataproc-cluster-uuid\ndataproc-cluster-name")
    stub_metadata_request('instance/attributes/dataproc-cluster-name',
                          DATAPROC_CLUSTER_NAME)
    stub_metadata_request('instance/attributes/dataproc-cluster-uuid',
                          DATAPROC_CLUSTER_UUID)
    stub_metadata_request('instance/attributes/dataproc-region',
                          DATAPROC_REGION)
  end

  def clear_metrics
    Prometheus::Client.registry.instance_variable_set('@metrics', {})
    OpenCensus::Stats.ensure_recorder.clear_stats
  end

  # Provide a stub context that initializes @logs_sent, executes the block and
  # resets WebMock at the end.
  def new_stub_context
    @logs_sent = []
    yield
    WebMock.reset!
  end

  # GKE Container.

  def container_tag_with_container_name(container_name)
    "kubernetes.#{K8S_POD_NAME}_#{K8S_NAMESPACE_NAME}_#{container_name}"
  end

  def container_log_entry_with_metadata(
      log, container_name = K8S_CONTAINER_NAME)
    {
      log: log,
      stream: K8S_STREAM,
      time: K8S_TIMESTAMP,
      kubernetes: {
        namespace_id: CONTAINER_NAMESPACE_ID,
        namespace_name: K8S_NAMESPACE_NAME,
        pod_id: CONTAINER_POD_ID,
        pod_name: K8S_POD_NAME,
        container_name: container_name,
        labels: {
          CONTAINER_LABEL_KEY => CONTAINER_LABEL_VALUE
        }
      }
    }
  end

  def container_log_entry(log, stream = K8S_STREAM)
    {
      log: log,
      stream: stream,
      time: K8S_TIMESTAMP
    }
  end

  def gke_container_log_entry(log)
    {
      log: log,
      LOCAL_RESOURCE_ID_KEY =>
        "#{CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{CONTAINER_NAMESPACE_ID}" \
        ".#{K8S_POD_NAME}.#{K8S_CONTAINER_NAME}"
    }
  end

  # TODO(qingling128): Temporary fallback for metadata agent restarts.
  # k8s resources.

  def k8s_container_log_entry(log,
                              local_resource_id: K8S_LOCAL_RESOURCE_ID)
    {
      log: log,
      stream: K8S_STREAM,
      time: K8S_TIMESTAMP,
      LOCAL_RESOURCE_ID_KEY => local_resource_id
    }
  end

  def k8s_pod_log_entry(log)
    {
      log: log,
      stream: K8S_STREAM,
      time: K8S_TIMESTAMP,
      LOCAL_RESOURCE_ID_KEY =>
        "#{K8S_POD_LOCAL_RESOURCE_ID_PREFIX}" \
        ".#{K8S_NAMESPACE_NAME}" \
        ".#{K8S_POD_NAME}"
    }
  end

  def k8s_node_log_entry(log)
    {
      log: log,
      stream: K8S_STREAM,
      time: K8S_TIMESTAMP,
      LOCAL_RESOURCE_ID_KEY =>
        "#{K8S_NODE_LOCAL_RESOURCE_ID_PREFIX}" \
        ".#{K8S_NODE_NAME}"
    }
  end

  def dataflow_log_entry(i)
    {
      step: DATAFLOW_STEP_ID,
      message: log_entry(i)
    }
  end

  def dataproc_log_entry(message, source_class = 'com.example.Example',
                         filename = 'test.log')
    {
      filename: filename,
      class: source_class,
      message: log_entry(message)
    }
  end

  def ml_log_entry(i)
    {
      name: ML_LOG_AREA,
      message: log_entry(i)
    }
  end

  def structured_log_entry
    {
      'name' => 'test name',
      'code' => 'test code'
    }
  end

  def log_entry(i)
    "test log entry #{i}"
  end

  # If check_exact_labels is true, assert 'labels' and 'expected_labels' match
  # exactly. If check_exact_labels is false, assert 'labels' is a subset of
  # 'expected_labels'.
  def check_labels(expected_labels, labels, check_exact_labels = true)
    return if expected_labels.empty? && labels.empty?
    expected_labels.each do |expected_key, expected_value|
      assert labels.key?(expected_key), "Expected label #{expected_key} not" \
             " found. Got labels: #{labels}."
      actual_value = labels[expected_key]
      assert actual_value.is_a?(String), 'Value for label' \
             " #{expected_key} is not a string: #{actual_value}."
      assert_equal expected_value, actual_value, "Value for #{expected_key}" \
                   " mismatch. Expected #{expected_value}. Got #{actual_value}"
    end
    if check_exact_labels
      assert_equal expected_labels.length, labels.length, 'Expected ' \
        "#{expected_labels.length} labels: #{expected_labels}, got " \
        "#{labels.length} labels: #{labels}"
    end
  end

  def verify_default_log_entry_text(text, i, entry)
    assert_equal "test log entry #{i}", text,
                 "Entry ##{i} had unexpected text: #{entry}"
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_json_log_entries(n, params, payload_type = 'textPayload',
                              check_exact_entry_labels = true)
    entry_count = 0
    @logs_sent.each do |request|
      request['entries'].each do |entry|
        unless payload_type.empty?
          assert entry.key?(payload_type),
                 "Entry ##{entry_count} did not contain expected" \
                 " #{payload_type} key: #{entry}."
        end

        # per-entry resource or log_name overrides the corresponding field
        # from the request.  Labels are merged, with the per-entry label
        # taking precedence in case of overlap.
        resource = entry['resource'] || request['resource']
        log_name = entry['logName'] || request['logName']

        labels ||= request['labels']
        labels.merge!(entry['labels'] || {})

        if params[:log_name]
          assert_equal \
            "projects/#{params[:project_id]}/logs/#{params[:log_name]}",
            log_name
        end
        assert_equal params[:resource][:type], resource['type']
        check_labels params[:resource][:labels], resource['labels']

        check_labels params[:labels], labels, check_exact_entry_labels

        if block_given?
          yield(entry, entry_count)
        elsif payload_type == 'textPayload'
          # Check the payload for textPayload, otherwise it's up to the caller.
          verify_default_log_entry_text(entry['textPayload'], entry_count,
                                        entry)
        end
        entry_count += 1
        assert entry_count <= n,
               "Number of entries #{entry_count} exceeds expected number #{n}."
      end
    end
    assert_equal n, entry_count
  end

  def verify_container_logs(log_entry_factory, expected_params)
    setup_gce_metadata_stubs
    setup_k8s_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        n.times { |i| d.emit(log_entry_factory.call(log_entry(i))) }
        d.run
      end
      verify_log_entries(n, expected_params) do |entry, i|
        verify_default_log_entry_text(entry['textPayload'], i, entry)
        actual_timestamp = timestamp_parse(entry['timestamp'])
        assert_equal K8S_SECONDS_EPOCH, actual_timestamp['seconds'], entry
        assert_equal K8S_NANOS, actual_timestamp['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['severity'], entry
      end
    end
  end

  def log_entry_subfields_params
    {
      # The keys are the names of fields in the payload that we are extracting
      # LogEntry info from. The values are lists of two elements: the name of
      # the subfield in LogEntry object and the expected value of that field.
      DEFAULT_HTTP_REQUEST_KEY => [
        'httpRequest', HTTP_REQUEST_MESSAGE],
      DEFAULT_LABELS_KEY => [
        'labels', COMPUTE_PARAMS[:labels].merge(LABELS_MESSAGE)],
      DEFAULT_OPERATION_KEY => [
        'operation', OPERATION_MESSAGE],
      DEFAULT_SOURCE_LOCATION_KEY => [
        'sourceLocation', SOURCE_LOCATION_MESSAGE]
    }
  end

  def verify_subfields_from_record(payload_key, check_exact_entry_labels = true)
    destination_key, payload_value = log_entry_subfields_params[payload_key]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => payload_value)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, destination_key,
                       check_exact_entry_labels) do |entry|
      assert_equal payload_value, entry[destination_key], entry
      fields = entry['jsonPayload']
      assert_nil fields[payload_key], entry
    end
  end

  def verify_subfields_partial_from_record(payload_key)
    destination_key, payload_value = log_entry_subfields_params[payload_key]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => payload_value.merge('otherKey' => 'value'))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, destination_key) do |entry|
      assert_equal payload_value, entry[destination_key], entry
      fields = entry['jsonPayload']
      request = fields[payload_key]
      assert_equal 'value', request['otherKey'], entry
    end
  end

  def verify_subfields_removed_when_not_hash(payload_key)
    destination_key = log_entry_subfields_params[payload_key][0]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => 'a_string')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      # The malformed field has been removed from the payload.
      assert_true entry['jsonPayload'].empty?, entry
      # No additional labels.
      assert_equal COMPUTE_PARAMS[:labels].size,
                   entry[destination_key].size, entry
    end
  end

  def verify_subfields_untouched_when_not_hash(payload_key)
    destination_key = log_entry_subfields_params[payload_key][0]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => 'a_string')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      # Verify that we leave the malformed field as it is.
      field = entry['jsonPayload'][payload_key]
      assert_equal 'a_string', field, entry
      assert_false entry.key?(destination_key), entry
    end
  end

  def verify_subfields_when_nil(payload_key)
    destination_key = log_entry_subfields_params[payload_key][0]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => nil)
      d.run
    end

    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_false fields.key?(payload_key), entry
      if payload_key == DEFAULT_LABELS_KEY
        # No additional labels.
        assert_equal COMPUTE_PARAMS[:labels].size,
                     entry[destination_key].size, entry
      else
        assert_false entry.key?(destination_key), entry
      end
    end
  end

  # Cascading JSON detection is only triggered when the record has one field
  # left with name "log", "message" or "msg". This test verifies additional
  # LogEntry fields like spanId and traceId do not disable that by accident.
  def verify_cascading_json_detection_with_log_entry_fields(
      log_entry_field, default_key, expectation)
    root_level_value = expectation[:root_level_value]
    nested_level_value = expectation[:nested_level_value]
    expected_value_from_root = expectation.fetch(
      :expected_value_from_root, root_level_value)
    expected_value_from_nested = expectation.fetch(
      :expected_value_from_nested, nested_level_value)
    default_value_from_root = expectation.fetch(
      :default_value_from_root, nil)
    default_value_from_nested = expectation.fetch(
      :default_value_from_nested, nil)

    setup_gce_metadata_stubs

    # {
    #   "logging.googleapis.com/XXX' => 'sample value'
    #   "msg": {
    #     "name": "test name",
    #     "code": "test code"
    #   }
    # }
    log_entry_with_root_level_field = {
      default_key => root_level_value,
      'msg' => structured_log_entry.to_json
    }
    # {
    #   "msg": {
    #     "logging.googleapis.com/XXX' => 'another value',
    #     "name": "test name",
    #     "code": "test code"
    #   }
    # }
    log_entry_with_nested_level_field = {
      'msg' => {
        default_key => nested_level_value
      }.merge(structured_log_entry).to_json
    }
    # {
    #   "logging.googleapis.com/XXX' => 'sample value'
    #   "msg": {
    #     "logging.googleapis.com/XXX' => 'another value',
    #     "name": "test name",
    #     "code": "test code"
    #   }
    # }
    log_entry_with_both_level_fields = log_entry_with_nested_level_field.merge(
      default_key => root_level_value)

    [
      [
        log_entry_with_root_level_field,
        expected_value_from_root,
        default_value_from_root
      ],
      [
        log_entry_with_nested_level_field,
        expected_value_from_nested,
        default_value_from_nested
      ],
      [
        log_entry_with_both_level_fields,
        expected_value_from_nested,
        default_value_from_nested
      ]
    ].each_with_index do |(log_entry, expected_value, default_value), index|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(DETECT_JSON_CONFIG)
        d.emit(log_entry)
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload', false) do |entry|
        assert_equal_with_default \
          entry[log_entry_field], expected_value, default_value,
          "Index #{index} failed. #{expected_value} is expected for " \
          "#{log_entry_field} field."
        payload_fields = entry['jsonPayload']
        assert_equal structured_log_entry.size, payload_fields.size
        payload_fields.each do |key, value|
          assert_equal structured_log_entry[key], value
        end
      end
    end
  end

  def verify_field_key(log_entry_field, test_params)
    default_key = test_params[:default_key]
    custom_key = test_params[:custom_key]
    custom_key_config = test_params[:custom_key_config]
    sample_value = test_params[:sample_value]
    default_value = test_params.fetch(:default_value, nil)

    setup_gce_metadata_stubs
    message = log_entry(0)
    [
      {
        # It leaves log entry field nil if no keyed value sent.
        driver_config: APPLICATION_DEFAULT_CONFIG,
        emitted_log: { 'msg' => message },
        expected_payload: { 'msg' => message },
        expected_field_value: default_value
      },
      {
        # By default, it sets log entry field via a default key.
        driver_config: APPLICATION_DEFAULT_CONFIG,
        emitted_log: { 'msg' => message, default_key => sample_value },
        expected_payload: { 'msg' => message },
        expected_field_value: sample_value
      },
      {
        # It allows setting the log entry field via a custom configured key.
        driver_config: custom_key_config,
        emitted_log: { 'msg' => message, custom_key => sample_value },
        expected_payload: { 'msg' => message },
        expected_field_value: sample_value
      },
      {
        # It doesn't set log entry field by default key if custom key specified.
        driver_config: custom_key_config,
        emitted_log: { 'msg' => message, default_key => sample_value },
        expected_payload: { 'msg' => message, default_key => sample_value },
        expected_field_value: default_value
      }
    ].each do |input|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(input[:driver_config])
        d.emit(input[:emitted_log])
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload', false) do |entry|
        assert_equal input[:expected_field_value], entry[log_entry_field], input
        payload_fields = entry['jsonPayload']
        assert_equal input[:expected_payload].size, payload_fields.size, input
        payload_fields.each do |key, value|
          assert_equal input[:expected_payload][key], value
        end
      end
    end
  end

  # Replace the 'referer' field with nil.
  def http_request_message_with_nil_referer
    HTTP_REQUEST_MESSAGE.merge('referer' => nil)
  end

  # Unset the 'referer' field.
  def http_request_message_with_absent_referer
    HTTP_REQUEST_MESSAGE.reject do |k, _|
      k == 'referer'
    end
  end

  # The conversions from user input to output.
  def latency_conversion
    _undefined
  end

  # This module expects the methods below to be overridden.

  # Create a Fluentd output test driver with the Google Cloud Output plugin.
  def create_driver(_conf = APPLICATION_DEFAULT_CONFIG, _tag = 'test')
    _undefined
  end

  # Set up http or grpc stubs to mock the external calls.
  def setup_logging_stubs
    _undefined
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(_n, _params, _payload_type = 'textPayload',
                         _check_exact_entry_labels = true, &_block)
    _undefined
  end

  # Defined in specific gRPC or REST files.
  def expected_operation_message2
    _undefined
  end

  # Parse timestamp and convert it to a hash with the "seconds" and "nanos" keys
  # if necessary.
  # Defined in specific gRPC or REST files.
  def timestamp_parse(_timestamp)
    _undefined
  end

  def _undefined
    raise "Method #{__callee__} is unimplemented and needs to be overridden."
  end
end
