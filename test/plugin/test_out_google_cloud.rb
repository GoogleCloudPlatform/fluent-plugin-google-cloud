# Copyright 2014 Google Inc. All rights reserved.
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
require 'json'
require 'mocha/test_unit'
require 'time'
require 'webmock/test_unit'

require_relative 'base_test'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputTest < GoogleCloudPluginBaseTest
  def test_configure_service_account_application_default
    setup_gce_metadata_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)
    assert_equal HOSTNAME, d.instance.vm_name
  end

  def test_configure_service_account_private_key
    # Using out-of-date config method.
    setup_gce_metadata_stubs
    exception_count = 0
    begin
      _d = create_driver(PRIVATE_KEY_CONFIG)
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

  def test_configure_invalid_metadata_missing_project_id_no_metadata_service
    setup_no_metadata_service_stubs
    exception_count = 0
    begin
      _d = create_driver(CONFIG_MISSING_METADATA_PROJECT_ID)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_configure_invalid_metadata_missing_zone_no_metadata_service
    setup_no_metadata_service_stubs
    exception_count = 0
    begin
      _d = create_driver(CONFIG_MISSING_METADATA_ZONE)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'zone'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_configure_invalid_metadata_missing_vm_id_no_metadata_service
    setup_no_metadata_service_stubs
    exception_count = 0
    begin
      _d = create_driver(CONFIG_MISSING_METADATA_VM_ID)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'vm_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_configure_invalid_metadata_missing_all_no_metadata_service
    setup_no_metadata_service_stubs
    exception_count = 0
    begin
      _d = create_driver(CONFIG_MISSING_METADATA_ALL)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      assert error.message.include? 'zone'
      assert error.message.include? 'vm_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
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
    # This would cause the service to be container.googleapis.com if not for the
    # detect_subservice=false config.
    setup_container_metadata_stubs
    d = create_driver(NO_DETECT_SUBSERVICE_CONFIG)
    d.run
    assert_equal COMPUTE_SERVICE_NAME, d.instance.service_name
  end

  def test_metadata_overrides_on_gce
    # In this case we are overriding all configured parameters so we should
    # see all "custom" values rather than the ones from the metadata server.
    setup_gce_metadata_stubs
    d = create_driver(CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_metadata_partial_overrides_on_gce
    # Similar to above, but we are not overriding project_id in this config
    # so we should see the metadata value for project_id and "custom" otherwise.
    setup_gce_metadata_stubs
    d = create_driver(CONFIG_MISSING_METADATA_PROJECT_ID)
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_ec2_metadata_loading
    setup_ec2_metadata_stubs
    d = create_driver(CONFIG_EC2_PROJECT_ID)
    d.run
    assert_equal EC2_PROJECT_ID, d.instance.project_id
    assert_equal EC2_PREFIXED_ZONE, d.instance.zone
    assert_equal EC2_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_ec2_metadata_partial_override
    setup_ec2_metadata_stubs
    d = create_driver(CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID)
    d.run
    assert_equal EC2_PROJECT_ID, d.instance.project_id
    assert_equal EC2_PREFIXED_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_ec2_metadata_requires_project_id
    setup_ec2_metadata_stubs
    exception_count = 0
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    begin
      _d = create_driver
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
    setup_logging_stubs
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_json_credentials
    setup_gce_metadata_stubs
    setup_logging_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_invalid_json_credentials
    setup_gce_metadata_stubs
    setup_logging_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = INVALID_CREDENTIALS[:path]
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

  def test_one_log_custom_metadata
    # don't set up any metadata stubs, so the test will fail if we try to
    # fetch metadata (and explicitly check this as well).
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_logging_stubs
    d = create_driver(NO_METADATA_SERVICE_CONFIG + CUSTOM_METADATA_CONFIG)
    d.emit('message' => log_entry(0))
    d.run
    verify_log_entries(1, CUSTOM_PARAMS)
  end

  def test_one_log_ec2
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_logging_stubs
    d = create_driver(CONFIG_EC2_PROJECT_ID)
    d.emit('message' => log_entry(0))
    d.run
    verify_log_entries(1, EC2_PARAMS)
  end

  def test_struct_payload_log
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000)
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
    end
  end

  def test_struct_payload_json_log
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
    d.emit('message' => 'notJSON ' + json_string)
    d.emit('message' => json_string)
    d.emit('message' => "\t" + json_string)
    d.emit('message' => '  ' + json_string)
    d.run
    verify_log_entries(4, COMPUTE_PARAMS, '') do |entry|
      assert entry.key?('textPayload'), 'Entry did not have textPayload'
    end
  end

  def test_struct_payload_json_container_log
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
    d.emit(container_log_entry_with_metadata('notJSON' + json_string))
    d.emit(container_log_entry_with_metadata(json_string))
    d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
    d.run
    log_index = 0
    verify_log_entries(3, CONTAINER_FROM_METADATA_PARAMS, '') do |entry|
      log_index += 1
      if log_index == 1
        assert entry.key?('textPayload'), 'Entry did not have textPayload'
      else
        assert entry.key?('structPayload'), 'Entry did not have structPayload'
        assert_equal 3, entry['structPayload'].size, entry
        assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
        assert_equal 'test', entry['structPayload']['tag2'], entry
        assert_equal 5000, entry['structPayload']['data'], entry
      end
    end
  end

  def test_timestamps
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    expected_ts = []
    emit_index = 0
    [Time.at(123_456.789), Time.at(0), Time.now].each do |ts|
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
    end
    d.run
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal expected_ts[verify_index].tv_sec,
                   entry['metadata']['timestamp']['seconds'], entry
      # Fluentd v0.14 onwards supports nanosecond timestamp values.
      # Added in 600 ns delta to avoid flaky tests introduced
      # due to rounding error in double-precision floating-point numbers
      # (to account for the missing 9 bits of precision ~ 512 ns).
      # See http://wikipedia.org/wiki/Double-precision_floating-point_format
      assert_in_delta expected_ts[verify_index].tv_nsec,
                      entry['metadata']['timestamp']['nanos'], 600, entry
      verify_index += 1
    end
  end

  def test_malformed_timestamp
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    # if timestamp is not a hash it is passed through to the struct payload.
    d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      assert_equal 2, entry['structPayload'].size, entry
      assert_equal 'not-a-hash', entry['structPayload']['timestamp'], entry
    end
  end

  def test_severities
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    expected_severity = []
    emit_index = 0
    # Array of pairs of [parsed_severity, expected_severity]
    [%w(INFO INFO), %w(warn WARNING), %w(E ERROR), %w(BLAH DEFAULT),
     ['105', 100], ['', 'DEFAULT']].each do |sev|
      d.emit('message' => log_entry(emit_index), 'severity' => sev[0])
      expected_severity.push(sev[1])
      emit_index += 1
    end
    d.run
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal expected_severity[verify_index],
                   entry['metadata']['severity'], entry
      verify_index += 1
    end
  end

  def test_label_map_without_field_present
    setup_gce_metadata_stubs
    setup_logging_stubs
    config = %(label_map { "label_field": "sent_label" })
    d = create_driver(config)
    d.emit('message' => log_entry(0))
    d.run
    # No additional labels should be present
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_label_map_with_field_present
    setup_gce_metadata_stubs
    setup_logging_stubs
    config = %(label_map { "label_field": "sent_label" })
    d = create_driver(config)
    d.emit('message' => log_entry(0), 'label_field' => 'label_value')
    d.run
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = 'label_value'
    verify_log_entries(1, params)
  end

  def test_label_map_with_numeric_field
    setup_gce_metadata_stubs
    setup_logging_stubs
    config = %(label_map { "label_field": "sent_label" })
    d = create_driver(config)
    d.emit('message' => log_entry(0), 'label_field' => 123_456_789)
    d.run
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '123456789'
    verify_log_entries(1, params)
  end

  def test_label_map_with_hash_field
    setup_gce_metadata_stubs
    setup_logging_stubs
    config = %(label_map { "label_field": "sent_label" })
    d = create_driver(config)
    # I'm not sure this actually makes sense for a user to do, but make
    # sure that it works if they try it.
    d.emit('message' => log_entry(0),
           'label_field' => { 'k1' => 10, 'k2' => 'val' })
    d.run
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '{"k1"=>10, "k2"=>"val"}'
    verify_log_entries(1, params)
  end

  def test_label_map_with_multiple_fields
    setup_gce_metadata_stubs
    setup_logging_stubs
    config = %(
      label_map {
        "label1": "sent_label_1",
        "label_number_two": "foo.googleapis.com/bar",
        "label3": "label3"
      }
    )
    d = create_driver(config)
    # not_a_label passes through to the struct payload
    d.emit('message' => log_entry(0),
           'label1' => 'value1',
           'label_number_two' => 'value2',
           'not_a_label' => 'value4',
           'label3' => 'value3')
    d.run
    # make a deep copy of COMPUTE_PARAMS and add the parsed labels.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label_1'] = 'value1'
    params[:labels]['foo.googleapis.com/bar'] = 'value2'
    params[:labels]['label3'] = 'value3'
    verify_log_entries(1, params, 'structPayload') do |entry|
      assert_equal 2, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['message'], entry
      assert_equal 'value4', entry['structPayload']['not_a_label'], entry
    end
  end

  def test_multiple_logs
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    # Only test a few values because otherwise the test can take minutes.
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit('message' => log_entry(i)) }
      d.run
      verify_log_entries(n, COMPUTE_PARAMS)
    end
  end

  def test_malformed_log
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
    # if the entry is not a hash, the plugin should silently drop it.
    d.emit('a string is not a valid message')
    d.run
    assert @logs_sent.empty?
  end

  def test_client_400
    setup_gce_metadata_stubs
    # The API Client should not retry this and the plugin should consume
    # the exception.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS))
      .to_return(status: 400, body: 'Bad Request')
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), times: 1)
  end

  def test_server_error
    setup_gce_metadata_stubs
    # The API client should retry this once, then throw an exception which
    # gets propagated through the plugin.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS))
      .to_return(status: 500, body: 'Server Error')
    d = create_driver
    d.emit('message' => log_entry(0))
    exception_count = 0
    begin
      d.run
    rescue Google::Apis::ServerError => error
      assert_equal 'Server error', error.message
      exception_count += 1
    end
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), times: 1)
    assert_equal 1, exception_count
  end

  def test_one_managed_vm_log
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    verify_log_entries(1, VMENGINE_PARAMS)
  end

  def test_multiple_managed_vm_logs
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit('message' => log_entry(i)) }
      d.run
      verify_log_entries(n, VMENGINE_PARAMS)
    end
  end

  def test_one_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry_with_metadata(log_entry(0)))
    d.run
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
    end
  end

  def test_multiple_container_logs_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit(container_log_entry_with_metadata(log_entry(i))) }
      d.run
      verify_log_entries(n, CONTAINER_FROM_METADATA_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def test_one_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry(log_entry(0)))
    d.run
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
    end
  end

  def test_multiple_container_logs_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit(container_log_entry(log_entry(i))) }
      d.run
      verify_log_entries(n, CONTAINER_FROM_TAG_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def test_one_container_log_from_tag_stderr
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry(log_entry(0), 'stderr'))
    d.run
    expected_params = CONTAINER_FROM_TAG_PARAMS.merge(
      labels: { "#{CONTAINER_SERVICE_NAME}/stream" => 'stderr' }
    ) { |_, oldval, newval| oldval.merge(newval) }
    verify_log_entries(1, expected_params) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal 'ERROR', entry['metadata']['severity'], entry
    end
  end

  def test_struct_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                             '"tag2": "test", "data": 5000, ' \
                                             '"severity": "WARNING"}'))
    d.run
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS,
                       'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal 'WARNING', entry['metadata']['severity'], entry
    end
  end

  def test_struct_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                               '"tag2": "test", "data": 5000, ' \
                               '"severity": "W"}'))
    d.run
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS,
                       'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal 'WARNING', entry['metadata']['severity'], entry
    end
  end

  def test_one_cloudfunctions_log
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
    d.emit(cloudfunctions_log_entry(0))
    d.run
    verify_log_entries(1, CLOUDFUNCTIONS_PARAMS) do |entry|
      assert_equal 'DEBUG', entry['metadata']['severity'], entry
    end
  end

  def test_multiple_cloudfunctions_logs
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
      d.run
      verify_log_entries(n, CLOUDFUNCTIONS_PARAMS) do |entry|
        assert_equal 'DEBUG', entry['metadata']['severity'], entry
      end
    end
  end

  def test_one_cloudfunctions_log_text_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
    d.emit(cloudfunctions_log_entry_text_not_matched(0))
    d.run
    verify_log_entries(1, CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS) do |entry|
      assert_equal 'INFO', entry['metadata']['severity'], entry
    end
  end

  def test_multiple_cloudfunctions_logs_text_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CLOUDFUNCTIONS_TAG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit(cloudfunctions_log_entry_text_not_matched(i)) }
      d.run
      verify_log_entries(n, CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS) do |entry|
        assert_equal 'INFO', entry['metadata']['severity'], entry
      end
    end
  end

  def test_one_cloudfunctions_log_tag_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(cloudfunctions_log_entry(0))
    d.run
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS, '') do |entry|
      assert_equal '[D][2015-09-25T12:34:56.789Z][123-0] test log entry 0',
                   entry['textPayload'], entry
    end
  end

  def test_multiple_cloudfunctions_logs_tag_not_matched
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
      d.run
      i = 0
      params = CONTAINER_FROM_TAG_PARAMS
      verify_log_entries(n, params, '') do |entry|
        assert_equal "[D][2015-09-25T12:34:56.789Z][123-0] test log entry #{i}",
                     entry['textPayload'], entry
        i += 1
      end
    end
  end

  def test_http_request_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)
    d.emit('httpRequest' => HTTP_REQUEST_MESSAGE)
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
      assert_equal nil, entry['structPayload']['httpRequest'], entry
    end
  end

  def test_http_request_partial_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)
    d.emit('httpRequest' => HTTP_REQUEST_MESSAGE.merge('otherKey' => 'value'))
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal HTTP_REQUEST_MESSAGE, entry['httpRequest'], entry
      assert_equal 'value', entry['structPayload']['httpRequest']['otherKey'],
                   entry
    end
  end

  def test_http_request_when_not_hash
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)
    d.emit('httpRequest' => 'a_string')
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      assert_equal 'a_string', entry['structPayload']['httpRequest'], entry
      assert_equal nil, entry['httpRequest'], entry
    end
  end

  # Make parse_severity public so we can test it.
  class Fluent::GoogleCloudOutput # rubocop:disable Style/ClassAndModuleChildren
    public :parse_severity
  end

  def test_parse_severity
    test_obj = Fluent::GoogleCloudOutput.new

    # known severities should translate to themselves, regardless of case
    %w(DEFAULT DEBUG INFO NOTICE WARNING ERROR CRITICAL ALERT EMERGENCY).each \
      do |severity|
      assert_equal(severity, test_obj.parse_severity(severity))
      assert_equal(severity, test_obj.parse_severity(severity.downcase))
      assert_equal(severity, test_obj.parse_severity(severity.capitalize))
    end

    # numeric levels
    assert_equal(0, test_obj.parse_severity('0'))
    assert_equal(100, test_obj.parse_severity('100'))
    assert_equal(200, test_obj.parse_severity('200'))
    assert_equal(300, test_obj.parse_severity('300'))
    assert_equal(400, test_obj.parse_severity('400'))
    assert_equal(500, test_obj.parse_severity('500'))
    assert_equal(600, test_obj.parse_severity('600'))
    assert_equal(700, test_obj.parse_severity('700'))
    assert_equal(800, test_obj.parse_severity('800'))

    assert_equal(800, test_obj.parse_severity('900'))
    assert_equal(0, test_obj.parse_severity('1'))
    assert_equal(100, test_obj.parse_severity('105'))
    assert_equal(400, test_obj.parse_severity('420'))
    assert_equal(700, test_obj.parse_severity('799'))

    assert_equal(100, test_obj.parse_severity('105 '))
    assert_equal(100, test_obj.parse_severity('     105'))
    assert_equal(100, test_obj.parse_severity('     105    '))

    assert_equal('DEFAULT', test_obj.parse_severity('-100'))
    assert_equal('DEFAULT', test_obj.parse_severity('105 100'))

    # synonyms for existing log levels
    assert_equal('ERROR', test_obj.parse_severity('ERR'))
    assert_equal('WARNING', test_obj.parse_severity('WARN'))
    assert_equal('CRITICAL', test_obj.parse_severity('FATAL'))
    assert_equal('DEBUG', test_obj.parse_severity('TRACE'))
    assert_equal('DEBUG', test_obj.parse_severity('TRACE_INT'))
    assert_equal('DEBUG', test_obj.parse_severity('FINE'))
    assert_equal('DEBUG', test_obj.parse_severity('FINER'))
    assert_equal('DEBUG', test_obj.parse_severity('FINEST'))

    # single letters.
    assert_equal('DEBUG', test_obj.parse_severity('D'))
    assert_equal('INFO', test_obj.parse_severity('I'))
    assert_equal('NOTICE', test_obj.parse_severity('N'))
    assert_equal('WARNING', test_obj.parse_severity('W'))
    assert_equal('ERROR', test_obj.parse_severity('E'))
    assert_equal('CRITICAL', test_obj.parse_severity('C'))
    assert_equal('ALERT', test_obj.parse_severity('A'))
    assert_equal('ERROR', test_obj.parse_severity('e'))

    assert_equal('DEFAULT', test_obj.parse_severity('x'))
    assert_equal('DEFAULT', test_obj.parse_severity('-'))

    # leading/trailing whitespace should be stripped
    assert_equal('ERROR', test_obj.parse_severity('  ERROR'))
    assert_equal('ERROR', test_obj.parse_severity('ERROR  '))
    assert_equal('ERROR', test_obj.parse_severity('   ERROR  '))
    assert_equal('ERROR', test_obj.parse_severity("\t  ERROR  "))

    # space in the middle should not be stripped.
    assert_equal('DEFAULT', test_obj.parse_severity('ER ROR'))

    # anything else should translate to 'DEFAULT'
    assert_equal('DEFAULT', test_obj.parse_severity(''))
    assert_equal('DEFAULT', test_obj.parse_severity('garbage'))
    assert_equal('DEFAULT', test_obj.parse_severity('er'))
  end
end
