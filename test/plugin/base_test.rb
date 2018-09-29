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

require 'google/apis'
require 'helper'
require 'mocha/test_unit'
require 'webmock/test_unit'
require 'prometheus/client'

require_relative 'constants'

# Unit tests for Google Cloud Logging plugin
module BaseTest
  include Constants

  def setup
    Fluent::Test.setup
    # delete environment variables that googleauth uses to find credentials.
    ENV.delete(CREDENTIALS_PATH_ENV_VAR)
    # service account env.
    ENV.delete('PRIVATE_KEY_VAR')
    ENV.delete('CLIENT_EMAIL_VAR')
    # authorized_user env.
    ENV.delete('CLIENT_ID_VAR')
    ENV.delete('CLIENT_SECRET_VAR')
    ENV.delete('REFRESH_TOKEN_VAR')
    # home var, which is used to find $HOME/.gcloud/...
    ENV.delete('HOME')

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

  def test_configure_partial_success
    setup_gce_metadata_stubs
    {
      APPLICATION_DEFAULT_CONFIG => true,
      PARTIAL_SUCCESS_DISABLED_CONFIG => false
    }.each do |(config, partial_success)|
      d = create_driver(config)
      assert_equal partial_success,
                   d.instance.instance_variable_get(:@partial_success)
    end
  end

  def test_metadata_agent_url_customization
    [
      # If @metadata_agent_url is set, use that even if the environment
      # variable is set.
      [CUSTOM_METADATA_AGENT_URL_CONFIG, true, CUSTOM_METADATA_AGENT_URL],
      # If @metadata_agent_url is set and the environment variable is
      # not set, use @metadata_agent_url.
      [CUSTOM_METADATA_AGENT_URL_CONFIG, false, CUSTOM_METADATA_AGENT_URL],
      # If @metadata_agent_url is not set and the environment variable is set,
      # use the env.
      [APPLICATION_DEFAULT_CONFIG, true, METADATA_AGENT_URL_FROM_ENV],
      # If @metadata_agent_url is not set and the environment variable is
      # not set, fall back to the default.
      [APPLICATION_DEFAULT_CONFIG, false, DEFAULT_METADATA_AGENT_URL]
    ].each do |(config, url_from_env, expected_url)|
      ENV[METADATA_AGENT_URL_ENV_VAR] = METADATA_AGENT_URL_FROM_ENV if
        url_from_env
      setup_gce_metadata_stubs
      d = create_driver(ENABLE_METADATA_AGENT_CONFIG + config)
      assert_equal expected_url, d.instance.metadata_agent_url
      ENV.delete(METADATA_AGENT_URL_ENV_VAR)
    end
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 4, fields.size, entry
      verify_default_log_entry_text(get_string(fields['msg']), i, entry)
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal null_value, fields['some_null_field'], entry
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
            assert_nil entry['trace']
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 7, fields.size, entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['int_key']))['1']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['int_array_key']))['[1, 2, 3, 4]']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['string_array_key']))['["a", "b", "c"]']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['hash_key']))['{"some_key"=>"some_value"}']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['mixed_key']))['{"some_key"=>["a", "b", "c"]}']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['symbol_key']))['some_symbol']), entry
      assert_equal message, get_string(get_fields(get_struct(fields \
                   ['nil_key']))['']), entry
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
      fields = get_fields(entry['jsonPayload'])
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
      fields = get_fields(entry['jsonPayload'])
      assert !fields.key?('tag2'), 'Did not expect tag2'
      assert !fields.key?('data'), 'Did not expect data'
      assert !fields.key?('some_null_field'), 'Did not expect some_null_field'
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 4, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal null_value, fields['some_null_field'], entry
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
        fields = get_fields(entry['jsonPayload'])
        assert_equal 4, fields.size, entry
        assert_equal 'test log entry 0', get_string(fields['msg']), entry
        assert_equal 'test', get_string(fields['tag2']), entry
        assert_equal 5000, get_number(fields['data']), entry
        assert_equal null_value, fields['some_null_field'], entry
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
      setup_prometheus
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

  def test_timestamps
    setup_gce_metadata_stubs
    current_time = Time.now
    next_year = Time.mktime(current_time.year + 1)
    one_second_before_next_year = next_year - 1
    adjusted_to_last_year =
      one_second_before_next_year.to_datetime.prev_year.to_time
    one_second_into_next_year = next_year + 1
    one_day_into_next_year = next_year.to_date.next_day.to_time
    {
      APPLICATION_DEFAULT_CONFIG => {
        Time.at(123_456.789) => Time.at(123_456.789),
        Time.at(0) => Time.at(0),
        current_time => current_time,
        one_second_before_next_year => adjusted_to_last_year,
        next_year => Time.at(0),
        one_second_into_next_year => Time.at(0),
        one_day_into_next_year => Time.at(0)
      },
      NO_ADJUST_TIMESTAMPS_CONFIG => {
        Time.at(123_456.789) => Time.at(123_456.789),
        Time.at(0) => Time.at(0),
        current_time => current_time,
        one_second_before_next_year => one_second_before_next_year,
        next_year => next_year,
        one_second_into_next_year => one_second_into_next_year,
        one_day_into_next_year => one_day_into_next_year
      }
    }.each do |config, timestamps|
      timestamps.each do |ts, expected_ts|
        emit_index = 0
        setup_logging_stubs do
          @logs_sent = []
          d = create_driver(config)
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
            assert_equal_with_default entry['timestamp']['seconds'],
                                      expected_ts.tv_sec, 0, entry
            assert_equal_with_default \
              entry['timestamp']['nanos'],
              expected_ts.tv_nsec, 0, entry do
              # Fluentd v0.14 onwards supports nanosecond timestamp values.
              # Added in 600 ns delta to avoid flaky tests introduced
              # due to rounding error in double-precision floating-point numbers
              # (to account for the missing 9 bits of precision ~ 512 ns).
              # See http://wikipedia.org/wiki/Double-precision_floating-point_format.
              assert_in_delta expected_ts.tv_nsec,
                              entry['timestamp']['nanos'], 600, entry
            end
          end
        end
      end
    end
  end

  def test_malformed_timestamp
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      # if timestamp is not a hash it is passed through to the json payload.
      d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = get_fields(entry['jsonPayload'])
      assert_equal 2, fields.size, entry
      assert_equal 'not-a-hash', get_string(fields['timestamp']), entry
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 2, fields.size, entry
      verify_default_log_entry_text(get_string(fields['message']), i, entry)
      assert_equal 'value4', get_string(fields['not_a_label']), entry
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
      assert_equal K8S_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal K8S_NANOS, entry['timestamp']['nanos'], entry
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal K8S_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal K8S_NANOS, entry['timestamp']['nanos'], entry
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal K8S_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal K8S_NANOS, entry['timestamp']['nanos'], entry
      assert_equal 'WARNING', entry['severity'], entry
    end
  end

  def test_cloudfunctions_log
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
      end
      verify_log_entries(n, CLOUDFUNCTIONS_PARAMS) do |entry, i|
        verify_default_log_entry_text(entry['textPayload'], i, entry)
        assert_equal 'DEBUG', entry['severity'],
                     "Test with #{n} logs failed. \n#{entry}"
      end
    end
  end

  def test_cloudfunctions_logs_text_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(cloudfunctions_log_entry_text_not_matched(i)) }
        d.run
      end
      verify_log_entries(
        n, CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS) do |entry|
        assert_equal 'INFO', entry['severity'],
                     "Test with #{n} logs failed. \n#{entry}"
      end
    end
  end

  def test_multiple_cloudfunctions_logs_tag_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
      end
      verify_log_entries(n, CONTAINER_FROM_TAG_PARAMS, 'textPayload') \
        do |entry, i|
          assert_equal '[D][2015-09-25T12:34:56.789Z][123-0] test log entry ' \
                       "#{i}", entry['textPayload'],
                       "Test with #{n} logs failed. \n#{entry}"
        end
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

  def test_log_entry_http_request_field_from_record
    verify_subfields_from_record(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_source_location_field_from_record
    verify_subfields_from_record(DEFAULT_SOURCE_LOCATION_KEY)
  end

  def test_log_entry_operation_field_from_record
    verify_subfields_from_record(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_http_request_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_source_location_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_SOURCE_LOCATION_KEY)
  end

  def test_log_entry_operation_field_partial_from_record
    verify_subfields_partial_from_record(DEFAULT_OPERATION_KEY)
  end

  def test_log_entry_http_request_field_when_not_hash
    verify_subfields_when_not_hash(DEFAULT_HTTP_REQUEST_KEY)
  end

  def test_log_entry_source_location_field_when_not_hash
    verify_subfields_when_not_hash(DEFAULT_SOURCE_LOCATION_KEY)
  end

  def test_log_entry_operation_field_when_not_hash
    verify_subfields_when_not_hash(DEFAULT_OPERATION_KEY)
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
        assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
      end
    end
  end

  def test_http_request_with_latency
    setup_gce_metadata_stubs
    latency_conversion.each do |input, expected|
      setup_logging_stubs do
        d = create_driver
        @logs_sent = []
        d.emit('httpRequest' => http_request_message.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal http_request_message.merge('latency' => expected),
                     entry['httpRequest'], entry
        assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
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
        d.emit('httpRequest' => http_request_message.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal http_request_message, entry['httpRequest'], entry
        assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
      end
    end
  end

  def test_log_entry_trace_field
    verify_field_key('trace', DEFAULT_TRACE_KEY, 'custom_trace_key',
                     CONFIG_CUSTOM_TRACE_KEY_SPECIFIED, TRACE)
  end

  def test_log_entry_span_id_field
    verify_field_key('spanId', DEFAULT_SPAN_ID_KEY, 'custom_span_id_key',
                     CONFIG_CUSTOM_SPAN_ID_KEY_SPECIFIED, SPAN_ID)
  end

  def test_log_entry_insert_id_field
    verify_field_key('insertId', DEFAULT_INSERT_ID_KEY, 'custom_insert_id_key',
                     CONFIG_CUSTOM_INSERT_ID_KEY_SPECIFIED, INSERT_ID)
  end

  def test_cascading_json_detection_with_log_entry_trace_field
    verify_cascading_json_detection_with_log_entry_fields(
      'trace', DEFAULT_TRACE_KEY, TRACE, TRACE2)
  end

  def test_cascading_json_detection_with_log_entry_span_id_field
    verify_cascading_json_detection_with_log_entry_fields(
      'spanId', DEFAULT_SPAN_ID_KEY, SPAN_ID, SPAN_ID2)
  end

  def test_cascading_json_detection_with_log_entry_insert_id_field
    verify_cascading_json_detection_with_log_entry_fields(
      'insertId', DEFAULT_INSERT_ID_KEY, INSERT_ID, INSERT_ID2)
  end

  # Metadata Agent related tests.

  # Test enable_metadata_agent not set or set to false.
  def test_configure_enable_metadata_agent_default_and_false
    setup_gce_metadata_stubs
    [create_driver, create_driver(DISABLE_METADATA_AGENT_CONFIG)].each do |d|
      assert_false d.instance.instance_variable_get(:@enable_metadata_agent)
    end
  end

  # Test enable_metadata_agent set to true.
  def test_configure_enable_metadata_agent_true
    new_stub_context do
      setup_gce_metadata_stubs
      setup_metadata_agent_stubs
      d = create_driver(ENABLE_METADATA_AGENT_CONFIG)
      assert_true d.instance.instance_variable_get(:@enable_metadata_agent)
    end
  end

  # Docker Container.

  # Test textPayload logs from Docker container stdout / stderr.
  def test_docker_container_stdout_stderr_logs_text_payload
    [1, 2, 3, 5, 11, 50].each do |n|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs
        setup_logging_stubs do
          d = create_driver(DOCKER_CONTAINER_CONFIG)
          n.times do |i|
            d.emit(docker_container_stdout_stderr_log_entry(log_entry(i)))
          end
          d.run
        end
        verify_log_entries(n, DOCKER_CONTAINER_PARAMS)
        assert_requested_metadata_agent_stub("container.#{DOCKER_CONTAINER_ID}")
      end
    end
  end

  # Test jsonPayload logs from Docker container stdout / stderr.
  def test_docker_container_stdout_stderr_logs_json_payload
    [1, 2, 3, 5, 11, 50].each do |n|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs
        setup_logging_stubs do
          d = create_driver(DOCKER_CONTAINER_CONFIG)
          n.times do
            d.emit(docker_container_stdout_stderr_log_entry(
                     '{"msg": "test log entry ' \
                     "#{n}" \
                     '", "tag2": "test", "data": ' \
                     '5000, "severity": "WARNING"}'))
          end
          d.run
        end
        verify_log_entries(n, DOCKER_CONTAINER_PARAMS, 'jsonPayload') do |entry|
          fields = get_fields(entry['jsonPayload'])
          assert_equal 3, fields.size, entry
          assert_equal "test log entry #{n}", get_string(fields['msg']), entry
          assert_equal 'test', get_string(fields['tag2']), entry
          assert_equal 5000, get_number(fields['data']), entry
        end
        assert_requested_metadata_agent_stub("container.#{DOCKER_CONTAINER_ID}")
      end
    end
  end

  # Test logs from applications running in Docker containers. These logs have
  # the label "logging.googleapis.com/local_resource_id" set in the format of
  # "container.<container_name>".
  def test_docker_container_application_logs
    new_stub_context do
      setup_gce_metadata_stubs
      setup_metadata_agent_stubs
      setup_logging_stubs do
        # Metadata Agent is not enabled. Will call Docker Remote API for
        # container info.
        d = create_driver(ENABLE_METADATA_AGENT_CONFIG)
        d.emit(docker_container_application_log_entry(log_entry(0)))
        d.run
      end
      verify_log_entries(1, DOCKER_CONTAINER_PARAMS_NO_STREAM)
      assert_requested_metadata_agent_stub(
        "#{DOCKER_CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{DOCKER_CONTAINER_NAME}")
    end
  end

  # Test k8s_container monitored resource including the fallback when Metadata
  # Agent restarts.
  def test_k8s_container_monitored_resource_fallback
    [
      # When enable_metadata_agent is false.
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_FALLBACK
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_FALLBACK
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      },
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      },
      # When enable_metadata_agent is true.
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_FALLBACK
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_FROM_LOCAL
      },
      {
        config: CUSTOM_K8S_ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS_CUSTOM
      },
      {
        config: EMPTY_K8S_ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: false,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(log_entry(0)),
        expected_params: K8S_CONTAINER_PARAMS
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs(test_params[:setup_metadata_agent_stub])
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config], CONTAINER_TAG)
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params],
                           'jsonPayload') do |entry|
          fields = get_fields(entry['jsonPayload'])
          assert_equal 2, fields.size, entry
          assert_equal 'test log entry 0', get_string(fields['log']), entry
          assert_equal K8S_STREAM, get_string(fields['stream']), entry
        end
      end
    end
  end

  def test_k8s_container_monitored_resource_invalid_local_resource_id
    [
      # When local_resource_id is not present or does not match k8s regexes.
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(
          log_entry(0)).reject { |k, _| k == LOCAL_RESOURCE_ID_KEY },
        expected_params: CONTAINER_FROM_TAG_PARAMS
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_container_log_entry(
          log_entry(0),
          local_resource_id: RANDOM_LOCAL_RESOURCE_ID),
        expected_params: CONTAINER_FROM_TAG_PARAMS
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs(test_params[:setup_metadata_agent_stub])
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

  # Test k8s_node monitored resource including the fallback when Metadata Agent
  # restarts.
  def test_k8s_node_monitored_resource_fallback
    [
      {
        config: APPLICATION_DEFAULT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_FROM_LOCAL
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_FROM_LOCAL
      },
      {
        config: CUSTOM_K8S_ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: false,
        setup_k8s_stub: false,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS_CUSTOM
      },
      {
        config: EMPTY_K8S_ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS
      },
      {
        config: ENABLE_METADATA_AGENT_CONFIG,
        setup_metadata_agent_stub: true,
        setup_k8s_stub: true,
        log_entry: k8s_node_log_entry(log_entry(0)),
        expected_params: K8S_NODE_PARAMS
      }
    ].each do |test_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs(test_params[:setup_metadata_agent_stub])
        setup_k8s_metadata_stubs(test_params[:setup_k8s_stub])
        setup_logging_stubs do
          d = create_driver(test_params[:config])
          d.emit(test_params[:log_entry])
          d.run
        end
        verify_log_entries(1, test_params[:expected_params],
                           'jsonPayload') do |entry|
          fields = get_fields(entry['jsonPayload'])
          assert_equal 2, fields.size, entry
          assert_equal 'test log entry 0', get_string(fields['log']), entry
          assert_equal K8S_STREAM, get_string(fields['stream']), entry
        end
      end
    end
  end

  # Test that the 'time' field from the json record is extracted and set to
  # entry.timestamp for Docker container logs.
  def test_time_field_extraction_for_docker_container_logs
    new_stub_context do
      setup_gce_metadata_stubs
      setup_metadata_agent_stubs
      setup_logging_stubs do
        d = create_driver(ENABLE_METADATA_AGENT_CONFIG)
        d.emit(docker_container_application_log_entry(log_entry(0)))
        d.run
      end
      verify_log_entries(1, DOCKER_CONTAINER_PARAMS_NO_STREAM) do |entry, i|
        verify_default_log_entry_text(entry['textPayload'], i, entry)
        # Timestamp in 'time' field from log entry should be set properly.
        assert_equal DOCKER_CONTAINER_SECONDS_EPOCH,
                     entry['timestamp']['seconds'], entry
        assert_equal DOCKER_CONTAINER_NANOS,
                     entry['timestamp']['nanos'], entry
      end
      assert_requested_metadata_agent_stub(
        "#{DOCKER_CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{DOCKER_CONTAINER_NAME}")
    end
  end

  # Test that the 'source' field is properly extracted from the record json and
  # set as a common label 'stream'.
  def test_source_for_docker_container_logs
    {
      docker_container_stdout_stderr_log_entry(
        log_entry(0), DOCKER_CONTAINER_STREAM_STDOUT) =>
        DOCKER_CONTAINER_PARAMS,
      docker_container_stdout_stderr_log_entry(
        log_entry(0), DOCKER_CONTAINER_STREAM_STDERR) =>
        DOCKER_CONTAINER_PARAMS_STREAM_STDERR,
      docker_container_application_log_entry(log_entry(0)) =>
        DOCKER_CONTAINER_PARAMS_NO_STREAM,
      docker_container_application_log_entry(log_entry(0)) \
        .merge('severity' => 'warning') =>
        DOCKER_CONTAINER_PARAMS_NO_STREAM
    }.each do |log_entry, expected_params|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_metadata_agent_stubs
        setup_logging_stubs do
          d = create_driver(DOCKER_CONTAINER_CONFIG)
          d.emit(log_entry)
          d.run
        end
        verify_log_entries(1, expected_params)
      end
    end
  end

  # Test GKE container logs. These logs have the label
  # "logging.googleapis.com/local_resource_id" set in the format of
  # "gke_container.<namespace_id>.<pod_name>.<container_name>".
  def test_gke_container_logs
    [1, 2, 3, 5, 11, 50].each do |n|
      new_stub_context do
        setup_gce_metadata_stubs
        setup_k8s_metadata_stubs
        setup_metadata_agent_stubs
        setup_logging_stubs do
          d = create_driver(ENABLE_METADATA_AGENT_CONFIG)
          n.times do |i|
            d.emit(gke_container_log_entry(log_entry(i)))
          end
          d.run
        end
        verify_log_entries(n, CONTAINER_FROM_APPLICATION_PARAMS)
        assert_requested_metadata_agent_stub(
          "#{CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{CONTAINER_NAMESPACE_ID}" \
          ".#{K8S_POD_NAME}.#{K8S_CONTAINER_NAME}")
      end
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

  def setup_cloudfunctions_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\ncluster-location\ncluster-name\ngcf_region\nlast_attribute")
    stub_metadata_request('instance/attributes/cluster-location',
                          K8S_LOCATION2)
    stub_metadata_request('instance/attributes/cluster-name',
                          K8S_CLUSTER_NAME)
    stub_metadata_request('instance/attributes/gcf_region',
                          CLOUDFUNCTIONS_REGION)
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

  def setup_prometheus
    Prometheus::Client.registry.instance_variable_set('@metrics', {})
  end

  # Metadata Agent.

  def metadata_request_url(local_resource_id)
    "#{DEFAULT_METADATA_AGENT_URL}/monitoredResource/#{local_resource_id}"
  end

  # Provide a stub context that initializes @logs_sent, executes the block and
  # resets WebMock at the end.
  def new_stub_context
    @logs_sent = []
    yield
    WebMock.reset!
  end

  def setup_metadata_agent_stubs(should_respond = true)
    if should_respond
      MONITORED_RESOURCE_STUBS.each do |local_resource_id, resource|
        stub_request(:get, metadata_request_url(local_resource_id))
          .to_return(status: 200, body: resource)
      end
      stub_request(:get, metadata_request_url(RANDOM_LOCAL_RESOURCE_ID))
        .to_return(status: 404, body: '')
    else
      # Simulate an environment with no metadata agent endpoint present.
      stub_request(:get,
                   %r{#{DEFAULT_METADATA_AGENT_URL}\/monitoredResource/.*})
        .to_raise(Errno::EHOSTUNREACH)
    end
  end

  def assert_requested_metadata_agent_stub(local_resource_id)
    assert_requested :get, metadata_request_url(local_resource_id)
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

  # Docker Container.

  def docker_container_stdout_stderr_log_entry(
    log, stream = DOCKER_CONTAINER_STREAM_STDOUT)
    severity = if stream == DOCKER_CONTAINER_STREAM_STDOUT
                 'INFO'
               else
                 'ERROR'
               end
    {
      log: log,
      source: stream,
      severity: severity,
      LOCAL_RESOURCE_ID_KEY => "container.#{DOCKER_CONTAINER_ID}"
    }
  end

  def docker_container_application_log_entry(log)
    {
      log: log,
      time: DOCKER_CONTAINER_TIMESTAMP,
      LOCAL_RESOURCE_ID_KEY => "#{DOCKER_CONTAINER_LOCAL_RESOURCE_ID_PREFIX}." \
                               "#{DOCKER_CONTAINER_NAME}"
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

  def cloudfunctions_log_entry(i)
    {
      stream: 'stdout',
      log: '[D][2015-09-25T12:34:56.789Z][123-0] ' + log_entry(i)
    }
  end

  def cloudfunctions_log_entry_text_not_matched(i)
    {
      stream: 'stdout',
      log: log_entry(i)
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

  def check_labels(labels, expected_labels)
    return if labels.empty? && expected_labels.empty?
    labels.each do |key, value|
      assert value.is_a?(String), "Value #{value} for label #{key} " \
        'is not a string: ' + value.class.name
      assert expected_labels.key?(key), "Unexpected label #{key} => #{value}"
      assert_equal expected_labels[key], value, 'Value mismatch - expected ' \
        "#{expected_labels[key]} in #{key} => #{value}"
    end
    assert_equal expected_labels.length, labels.length, 'Expected ' \
      "#{expected_labels.length} labels: #{expected_labels}, got " \
      "#{labels.length} labels: #{labels}"
  end

  def verify_default_log_entry_text(text, i, entry)
    assert_equal "test log entry #{i}", text,
                 "Entry ##{i} had unexpected text: #{entry}"
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_json_log_entries(n, params, payload_type = 'textPayload')
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
        check_labels resource['labels'], params[:resource][:labels]
        check_labels labels, params[:labels]
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
        assert_equal K8S_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
        assert_equal K8S_NANOS, entry['timestamp']['nanos'], entry
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
        'httpRequest', http_request_message],
      DEFAULT_SOURCE_LOCATION_KEY => [
        'sourceLocation', source_location_message],
      DEFAULT_OPERATION_KEY => [
        'operation', OPERATION_MESSAGE]
    }
  end

  def verify_subfields_from_record(payload_key)
    destination_key, payload_value = log_entry_subfields_params[payload_key]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => payload_value)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, destination_key) do |entry|
      assert_equal payload_value, entry[destination_key], entry
      fields = get_fields(entry['jsonPayload'])
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
      fields = get_fields(entry['jsonPayload'])
      request = get_fields(get_struct(fields[payload_key]))
      assert_equal 'value', get_string(request['otherKey']), entry
    end
  end

  def verify_subfields_when_not_hash(payload_key)
    destination_key = log_entry_subfields_params[payload_key][0]
    @logs_sent = []
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit(payload_key => 'a_string')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      field = get_fields(entry['jsonPayload'])[payload_key]
      assert_equal 'a_string', get_string(field), entry
      assert_nil entry[destination_key], entry
    end
  end

  # Cascading JSON detection is only triggered when the record has one field
  # left with name "log", "message" or "msg". This test verifies additional
  # LogEntry fields like spanId and traceId do not disable that by accident.
  def verify_cascading_json_detection_with_log_entry_fields(
      log_entry_field, default_key, root_level_value, nested_level_value)
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

    {
      log_entry_with_root_level_field => root_level_value,
      log_entry_with_nested_level_field => nested_level_value,
      log_entry_with_both_level_fields => nested_level_value
    }.each_with_index do |(input_log_entry, expected_value), index|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(DETECT_JSON_CONFIG)
        d.emit(input_log_entry)
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
        assert_equal expected_value, entry[log_entry_field],
                     "Index #{index} failed. #{expected_value} is expected" \
                     " for #{log_entry_field} field."
        payload_fields = get_fields(entry['jsonPayload'])
        assert_equal structured_log_entry.size, payload_fields.size
        payload_fields.each do |key, value|
          assert_equal structured_log_entry[key], get_string(value)
        end
      end
    end
  end

  def verify_field_key(log_entry_field, default_key, custom_key,
                       custom_key_config, sample_value)
    setup_gce_metadata_stubs
    message = log_entry(0)
    [
      {
        # It leaves log entry field nil if no keyed value sent.
        driver_config: APPLICATION_DEFAULT_CONFIG,
        emitted_log: { 'msg' => message },
        expected_payload: { 'msg' => message },
        expected_field_value: nil
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
        expected_field_value: nil
      }
    ].each do |input|
      setup_logging_stubs do
        @logs_sent = []
        d = create_driver(input[:driver_config])
        d.emit(input[:emitted_log])
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
        assert_equal input[:expected_field_value], entry[log_entry_field], input
        payload_fields = get_fields(entry['jsonPayload'])
        assert_equal input[:expected_payload].size, payload_fields.size, input
        payload_fields.each do |key, value|
          assert_equal input[:expected_payload][key], get_string(value), input
        end
      end
    end
  end

  def http_request_message
    HTTP_REQUEST_MESSAGE
  end

  def source_location_message
    SOURCE_LOCATION_MESSAGE
  end

  # Replace the 'referer' field with nil.
  def http_request_message_with_nil_referer
    http_request_message.merge('referer' => nil)
  end

  # Unset the 'referer' field.
  def http_request_message_with_absent_referer
    http_request_message.reject do |k, _|
      k == 'referer'
    end
  end

  # The conversions from user input to output.
  def latency_conversion
    {
      '32 s' => { 'seconds' => 32 },
      '32s' => { 'seconds' => 32 },
      '0.32s' => { 'nanos' => 320_000_000 },
      ' 123 s ' => { 'seconds' => 123 },
      '1.3442 s' => { 'seconds' => 1, 'nanos' => 344_200_000 },

      # Test whitespace.
      # \t: tab. \r: carriage return. \n: line break.
      # \v: vertical whitespace. \f: form feed.
      "\t123.5\ts\t" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\r123.5\rs\r" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\n123.5\ns\n" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\v123.5\vs\v" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\f123.5\fs\f" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\r123.5\ts\f" => { 'seconds' => 123, 'nanos' => 500_000_000 }
    }
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
  def verify_log_entries(_n, _params, _payload_type = 'textPayload', &_block)
    _undefined
  end

  # For an optional field with default values, Protobuf omits the field when it
  # is deserialized to json. So we need to add an extra check for gRPC which
  # uses Protobuf.
  #
  # An optional block can be passed in if we need to assert something other than
  # a plain equal. e.g. assert_in_delta.
  def assert_equal_with_default(_field, _expected_value, _default_value, _entry)
    _undefined
  end

  def assert_prometheus_metric_value(metric_name, expected_value, labels = {})
    metric = Prometheus::Client.registry.get(metric_name)
    assert_not_nil(metric)
    metric_value = if labels == :aggregate
                     # Sum up all metric values regardless of the labels.
                     metric.values.values.reduce(0.0, :+)
                   else
                     metric.get(labels)
                   end
    assert_equal(expected_value, metric_value)
  end

  # Get the fields of the payload.
  def get_fields(_payload)
    _undefined
  end

  # Get the value of a struct field.
  def get_struct(_field)
    _undefined
  end

  # Get the value of a string field.
  def get_string(_field)
    _undefined
  end

  # Get the value of a number field.
  def get_number(_field)
    _undefined
  end

  # The null value.
  def null_value(_field)
    _undefined
  end

  def _undefined
    raise "Method #{__callee__} is unimplemented and needs to be overridden."
  end
end
