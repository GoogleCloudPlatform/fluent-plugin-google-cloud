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

require_relative 'constants'

# Unit tests for Google Cloud Logging plugin
module BaseTest
  include Constants

  def setup
    Fluent::Test.setup
    # delete environment variables that googleauth uses to find credentials.
    ENV.delete('GOOGLE_APPLICATION_CREDENTIALS')
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

  def test_configure_custom_metadata
    setup_no_metadata_service_stubs
    d = create_driver(CUSTOM_METADATA_CONFIG)
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
  end

  def test_configure_invalid_metadata_missing_parts
    setup_no_metadata_service_stubs
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    { CONFIG_MISSING_METADATA_PROJECT_ID => ['project_id'],
      CONFIG_MISSING_METADATA_ZONE => ['zone'],
      CONFIG_MISSING_METADATA_VM_ID => ['vm_id'],
      CONFIG_MISSING_METADATA_ALL => %w(project_id zone vm_id)
    }.each_with_index do |(config, parts), index|
      exception_count = 0
      begin
        create_driver(config)
      rescue Fluent::ConfigError => error
        assert error.message.include?('Unable to obtain metadata parameters:'),
               "Index #{index} failed."
        parts.each do |part|
          assert error.message.include?(part), "Index #{index} failed."
        end
        exception_count += 1
      end
      assert_equal 1, exception_count, "Index #{index} failed."
    end
  end

  def test_metadata_loading
    setup_gce_metadata_stubs
    d = create_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_managed_vm_metadata_loading
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    d = create_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal true, d.instance.running_on_managed_vm
    assert_equal MANAGED_VM_BACKEND_NAME, d.instance.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.instance.gae_backend_version
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    d = create_driver(NO_METADATA_SERVICE_CONFIG + CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_gce_used_when_detect_subservice_is_false
    setup_gce_metadata_stubs
    # This would cause the resource type to be container.googleapis.com if not
    # for the detect_subservice=false config.
    setup_container_metadata_stubs
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
        ['ec2', EC2_PROJECT_ID, EC2_PREFIXED_ZONE, CUSTOM_VM_ID]
    }.each_with_index do |(config, parts), index|
      send("setup_#{parts[0]}_metadata_stubs")
      d = create_driver(config)
      d.run
      assert_equal parts[1], d.instance.project_id, "Index #{index} failed."
      assert_equal parts[2], d.instance.zone, "Index #{index} failed."
      assert_equal parts[3], d.instance.vm_id, "Index #{index} failed."
      assert_equal false, d.instance.running_on_managed_vm,
                   "Index #{index} failed."
    end
  end

  def test_ec2_metadata_requires_project_id
    setup_ec2_metadata_stubs
    exception_count = 0
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    begin
      create_driver
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_ec2_metadata_project_id_from_credentials
    setup_ec2_metadata_stubs
    [IAM_CREDENTIALS, LEGACY_CREDENTIALS].each do |creds|
      ENV['GOOGLE_APPLICATION_CREDENTIALS'] = creds[:path]
      d = create_driver
      d.run
      assert_equal creds[:project_id], d.instance.project_id
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
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_logging_stubs do
      d = create_driver
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_invalid_json_credentials
    setup_gce_metadata_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = INVALID_CREDENTIALS[:path]
    setup_logging_stubs do
      d = create_driver
      d.emit('message' => log_entry(0))
      exception_count = 0
      begin
        d.run
      rescue RuntimeError => error
        assert error.message.include? 'Unable to read the credential file'
        exception_count += 1
      end
      assert_equal 1, exception_count
    end
  end

  def test_one_log_custom_metadata
    # don't set up any metadata stubs, so the test will fail if we try to
    # fetch metadata (and explicitly check this as well).
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_logging_stubs do
      d = create_driver(NO_METADATA_SERVICE_CONFIG + CUSTOM_METADATA_CONFIG)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, CUSTOM_PARAMS)
  end

  def test_one_log_ec2
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_logging_stubs do
      d = create_driver(CONFIG_EC2_PROJECT_ID)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries(1, EC2_PARAMS)
  end

  def test_structured_payload_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000,
             'some_null_field' => nil)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = get_fields(entry['jsonPayload'])
      assert_equal 4, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal null_value, fields['some_null_field'], entry
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

  def test_structured_payload_json_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
      d.emit('message' => 'notJSON ' + json_string)
      d.emit('message' => json_string)
      d.emit('message' => "\t" + json_string)
      d.emit('message' => '  ' + json_string)
      d.run
    end
    verify_log_entries(4, COMPUTE_PARAMS, '') do |entry|
      assert entry.key?('textPayload'), 'Entry did not have textPayload'
    end
  end

  def test_structured_payload_json_container_log
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      json_string = '{"msg": "test log entry 0", "tag2": "test", ' \
                    '"data": 5000, "some_null_field": null}'
      d.emit(container_log_entry_with_metadata('notJSON' + json_string))
      d.emit(container_log_entry_with_metadata(json_string))
      d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
      d.run
    end
    log_index = 0
    verify_log_entries(
      3, CONTAINER_FROM_METADATA_PARAMS, '') do |entry|
      log_index += 1
      if log_index == 1
        assert entry.key?('textPayload'), 'Entry did not have textPayload'
      else
        assert entry.key?('jsonPayload'), 'Entry did not have jsonPayload'
        fields = get_fields(entry['jsonPayload'])
        assert_equal 4, fields.size, entry
        assert_equal 'test log entry 0', get_string(fields['msg']), entry
        assert_equal 'test', get_string(fields['tag2']), entry
        assert_equal 5000, get_number(fields['data']), entry
        assert_equal null_value, fields['some_null_field'], entry
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
    setup_container_metadata_stubs
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
    setup_container_metadata_stubs
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
          "#{CONTAINER_CONSTANTS[:service]}/container_name" =>
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
    setup_container_metadata_stubs
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
    setup_container_metadata_stubs
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

  def test_timestamps
    setup_gce_metadata_stubs
    expected_ts = []
    emit_index = 0
    setup_logging_stubs do
      [Time.at(123_456.789), Time.at(0), Time.now].each do |ts|
        d = create_driver
        # Test the "native" fluentd timestamp as well as our nanosecond tags.
        d.emit({ 'message' => log_entry(emit_index) }, ts.to_f)
        expected_ts.push(ts)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timeNanos' => ts.tv_sec * 1_000_000_000 + ts.tv_nsec)
        expected_ts.push(ts)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timestamp' => { 'seconds' => ts.tv_sec, 'nanos' => ts.tv_nsec })
        expected_ts.push(ts)
        emit_index += 1
        d.emit('message' => log_entry(emit_index),
               'timestampSeconds' => ts.tv_sec, 'timestampNanos' => ts.tv_nsec)
        expected_ts.push(ts)
        emit_index += 1
        d.run
      end
    end
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal_with_default entry['timestamp']['seconds'],
                                expected_ts[verify_index].tv_sec, 0, entry
      assert_equal_with_default entry['timestamp']['nanos'],
                                expected_ts[verify_index].tv_nsec, 0, entry do
        # Fluentd v0.14 onwards supports nanosecond timestamp values.
        # Added in 600 ns delta to avoid flaky tests introduced
        # due to rounding error in double-precision floating-point numbers
        # (to account for the missing 9 bits of precision ~ 512 ns).
        # See http://wikipedia.org/wiki/Double-precision_floating-point_format
        assert_in_delta expected_ts[verify_index].tv_nsec,
                        entry['timestamp']['nanos'], 600, entry
      end
      verify_index += 1
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
    verify_log_entries(1, params, 'jsonPayload') do |entry|
      fields = get_fields(entry['jsonPayload'])
      assert_equal 2, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['message']), entry
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

  def test_one_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata(log_entry(0)))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['severity'], entry
    end
  end

  def test_multiple_container_logs_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(container_log_entry_with_metadata(log_entry(i))) }
        d.run
      end
      verify_log_entries(n, CONTAINER_FROM_METADATA_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'],
                     entry
        assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['severity'], entry
      end
    end
  end

  def test_multiple_container_logs_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs do
        d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(container_log_entry(log_entry(i))) }
        d.run
      end
      verify_log_entries(n, CONTAINER_FROM_TAG_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'],
                     entry
        assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['severity'], entry
      end
    end
  end

  def test_one_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0)))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['severity'], entry
    end
  end

  def test_one_container_log_from_tag_stderr
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0), 'stderr'))
      d.run
    end
    expected_params = CONTAINER_FROM_TAG_PARAMS.merge(
      labels: { "#{CONTAINER_CONSTANTS[:service]}/stream" => 'stderr' }
    ) { |_, oldval, newval| oldval.merge(newval) }
    verify_log_entries(1, expected_params) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
      assert_equal 'ERROR', entry['severity'], entry
    end
  end

  def test_json_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
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
      assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
      assert_equal 'WARNING', entry['severity'], entry
    end
  end

  def test_json_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
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
      assert_equal CONTAINER_SECONDS_EPOCH, entry['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, entry['timestamp']['nanos'], entry
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
      verify_log_entries(n, CLOUDFUNCTIONS_PARAMS) do |entry|
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
      i = 0
      verify_log_entries(n, CONTAINER_FROM_TAG_PARAMS, '') do |entry|
        assert_equal '[D][2015-09-25T12:34:56.789Z][123-0] test log entry ' \
                     "#{i}", entry['textPayload'],
                     "Test with #{n} logs failed. \n#{entry}"
        i += 1
      end
    end
  end

  def test_http_request_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => HTTP_REQUEST_MESSAGE)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
      assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
    end
  end

  def test_http_request_partial_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge(
        'otherKey' => 'value'))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
      fields = get_fields(entry['jsonPayload'])
      request = get_fields(get_struct(fields['httpRequest']))
      assert_equal 'value', get_string(request['otherKey']), entry
    end
  end

  def test_http_request_when_not_hash
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => 'a_string')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = get_fields(entry['jsonPayload'])
      assert_equal 'a_string', get_string(fields['httpRequest']), entry
      assert_nil entry['httpRequest'], entry
    end
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
        d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE.merge('latency' => expected),
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
        d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge('latency' => input))
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
        assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
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
    stub_request(:post, 'https://www.googleapis.com/oauth2/v3/token')
      .with(body: hash_including(grant_type: AUTH_GRANT_TYPE))
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })

    stub_request(:post, 'https://www.googleapis.com/oauth2/v3/token')
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

  def setup_container_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\nkube-env\nlast_attribute")
    stub_metadata_request('instance/attributes/kube-env',
                          "ENABLE_NODE_LOGGING: \"true\"\n"\
                          'INSTANCE_PREFIX: '\
                          "gke-#{CONTAINER_CLUSTER_NAME}-740fdafa\n"\
                          'KUBE_BEARER_TOKEN: AoQiMuwkNP2BMT0S')
  end

  def setup_cloudfunctions_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\nkube-env\ngcf_region\nlast_attribute")
    stub_metadata_request('instance/attributes/kube-env',
                          "ENABLE_NODE_LOGGING: \"true\"\n"\
                          'INSTANCE_PREFIX: '\
                          "gke-#{CLOUDFUNCTIONS_CLUSTER_NAME}-740fdafa\n"\
                          'KUBE_BEARER_TOKEN: AoQiMuwkNP2BMT0S')
    stub_metadata_request('instance/attributes/gcf_region',
                          CLOUDFUNCTIONS_REGION)
  end

  def container_tag_with_container_name(container_name)
    "kubernetes.#{CONTAINER_POD_NAME}_#{CONTAINER_NAMESPACE_NAME}_" \
      "#{container_name}"
  end

  def container_log_entry_with_metadata(
      log, container_name = CONTAINER_CONTAINER_NAME)
    {
      log: log,
      stream: CONTAINER_STREAM,
      time: CONTAINER_TIMESTAMP,
      kubernetes: {
        namespace_id: CONTAINER_NAMESPACE_ID,
        namespace_name: CONTAINER_NAMESPACE_NAME,
        pod_id: CONTAINER_POD_ID,
        pod_name: CONTAINER_POD_NAME,
        container_name: container_name,
        labels: {
          CONTAINER_LABEL_KEY => CONTAINER_LABEL_VALUE
        }
      }
    }
  end

  def container_log_entry(log, stream = CONTAINER_STREAM)
    {
      log: log,
      stream: stream,
      time: CONTAINER_TIMESTAMP
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

  def ml_log_entry(i)
    {
      name: ML_LOG_AREA,
      message: log_entry(i)
    }
  end

  def log_entry(i)
    'test log entry ' + i.to_s
  end

  def check_labels(labels, expected_labels)
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

  # The caller can optionally provide a block which is called for each entry.
  def verify_json_log_entries(n, params, payload_type = 'textPayload')
    i = 0
    @logs_sent.each do |request|
      request['entries'].each do |entry|
        unless payload_type.empty?
          assert entry.key?(payload_type), 'Entry did not contain expected ' \
            "#{payload_type} key: " + entry.to_s
          # Check the payload for textPayload, otherwise it's up to the caller.
          if payload_type == 'textPayload'
            assert_equal "test log entry #{i}", entry['textPayload'], request
          end
        end

        # per-entry resource or log_name overrides the corresponding field
        # from the request.  Labels are merged, with the per-entry label
        # taking precedence in case of overlap.
        resource = entry['resource'] || request['resource']
        log_name = entry['logName'] || request['logName']

        labels ||= request['labels']
        labels.merge!(entry['labels'] || {})

        assert_equal \
          "projects/#{params[:project_id]}/logs/#{params[:log_name]}", log_name
        assert_equal params[:resource][:type], resource['type']
        check_labels resource['labels'], params[:resource][:labels]
        check_labels labels, params[:labels]
        yield(entry) if block_given?
        i += 1
        assert i <= n, "Number of entries #{i} exceeds expected number #{n}"
      end
    end
    assert i == n, "Number of entries #{i} does not match expected number #{n}"
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
    fail "Method #{__callee__} is unimplemented and needs to be overridden."
  end
end
