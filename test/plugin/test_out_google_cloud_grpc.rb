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
require 'grpc'
require 'helper'
require 'json'
require 'mocha/test_unit'
require 'time'
require 'webmock/test_unit'

require_relative 'base_test'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputGRPCTest < GoogleCloudPluginBaseTest
  def test_configure_service_account_application_default_grpc
    setup_gce_metadata_stubs
    d = create_grpc_driver
    assert_equal HOSTNAME, d.instance.vm_name
  end

  def test_configure_service_account_private_key_grpc
    # Using out-of-date config method.
    setup_gce_metadata_stubs
    exception_count = 0
    begin
      create_grpc_driver(USE_GRPC_CONFIG + PRIVATE_KEY_CONFIG)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Please remove configuration parameters'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_configure_custom_metadata_grpc
    setup_no_metadata_service_stubs
    d = create_grpc_driver(USE_GRPC_CONFIG + CUSTOM_METADATA_CONFIG)
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
  end

  def test_configure_invalid_metadata_missing_parts_grpc
    setup_no_metadata_service_stubs
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    { CONFIG_MISSING_METADATA_PROJECT_ID => ['project_id'],
      CONFIG_MISSING_METADATA_ZONE => ['zone'],
      CONFIG_MISSING_METADATA_VM_ID => ['vm_id'],
      CONFIG_MISSING_METADATA_ALL => %w(project_id zone vm_id)
    }.each_with_index do |(config, parts), index|
      exception_count = 0
      begin
        create_grpc_driver(USE_GRPC_CONFIG + config)
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

  def test_metadata_loading_grpc
    setup_gce_metadata_stubs
    d = create_grpc_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_managed_vm_metadata_loading_grpc
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    d = create_grpc_driver
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal true, d.instance.running_on_managed_vm
    assert_equal MANAGED_VM_BACKEND_NAME, d.instance.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.instance.gae_backend_version
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false_grpc
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    d = create_grpc_driver(USE_GRPC_CONFIG + NO_METADATA_SERVICE_CONFIG +
                           CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_gce_used_when_detect_subservice_is_false_grpc
    setup_gce_metadata_stubs
    # This would cause the service to be container.googleapis.com if not for the
    # detect_subservice=false config.
    setup_container_metadata_stubs
    d = create_grpc_driver(USE_GRPC_CONFIG + NO_DETECT_SUBSERVICE_CONFIG)
    d.run
    assert_equal COMPUTE_SERVICE_NAME, d.instance.service_name
  end

  def test_configure_use_grpc
    setup_gce_metadata_stubs
    { create_driver => false,
      create_grpc_driver => true }.each do |driver, value|
      assert_equal value, driver.instance.instance_variable_get(:@use_grpc)
    end
  end

  def test_metadata_overrides_grpc
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
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
      d.run
      assert_equal parts[1], d.instance.project_id, "Index #{index} failed."
      assert_equal parts[2], d.instance.zone, "Index #{index} failed."
      assert_equal parts[3], d.instance.vm_id, "Index #{index} failed."
      assert_equal false, d.instance.running_on_managed_vm,
                   "Index #{index} failed."
    end
  end

  def test_ec2_metadata_requires_project_id_grpc
    setup_ec2_metadata_stubs
    exception_count = 0
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    begin
      create_grpc_driver
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_ec2_metadata_project_id_from_credentials_grpc
    setup_ec2_metadata_stubs
    [IAM_CREDENTIALS, LEGACY_CREDENTIALS].each do |creds|
      ENV['GOOGLE_APPLICATION_CREDENTIALS'] = creds[:path]
      d = create_grpc_driver
      d.run
      assert_equal creds[:project_id], d.instance.project_id
    end
  end

  def test_one_log_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('message' => log_entry(0))
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS)
    end
  end

  def test_one_log_with_json_credentials_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
      d = create_grpc_driver
      d.emit('message' => log_entry(0))
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS)
    end
  end

  def test_one_log_with_invalid_json_credentials_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      ENV['GOOGLE_APPLICATION_CREDENTIALS'] = INVALID_CREDENTIALS[:path]
      d = create_grpc_driver
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

  def test_one_log_custom_metadata_grpc
    # don't set up any metadata stubs, so the test will fail if we try to
    # fetch metadata (and explicitly check this as well).
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG + NO_METADATA_SERVICE_CONFIG +
        CUSTOM_METADATA_CONFIG)
      d.emit('message' => log_entry(0))
      d.run
      verify_grpc_log_entries(1, CUSTOM_PARAMS)
    end
  end

  def test_one_log_ec2_grpc
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG + CONFIG_EC2_PROJECT_ID)
      d.emit('message' => log_entry(0))
      d.run
      verify_grpc_log_entries(1, EC2_PARAMS)
    end
  end

  def test_struct_payload_log_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000)
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
        fields = entry['structPayload']['fields']
        assert_equal 3, fields.size, entry
        assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
        assert_equal 'test', fields['tag2']['stringValue'], entry
        assert_equal 5000, fields['data']['numberValue'], entry
      end
    end
  end

  def test_struct_payload_json_log_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
      d.emit('message' => 'notJSON ' + json_string)
      d.emit('message' => json_string)
      d.emit('message' => "\t" + json_string)
      d.emit('message' => '  ' + json_string)
      d.run
      verify_grpc_log_entries(4, COMPUTE_PARAMS, '') do |entry|
        assert entry.key?('textPayload'), 'Entry did not have textPayload'
      end
    end
  end

  def test_struct_payload_json_container_log_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
      d.emit(container_log_entry_with_metadata('notJSON' + json_string))
      d.emit(container_log_entry_with_metadata(json_string))
      d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
      d.run
      log_index = 0
      verify_grpc_log_entries(3, CONTAINER_FROM_METADATA_PARAMS, '') do |entry|
        log_index += 1
        if log_index == 1
          assert entry.key?('textPayload'), 'Entry did not have textPayload'
        else
          assert entry.key?('structPayload'), 'Entry did not have structPayload'
          fields = entry['structPayload']['fields']
          assert_equal 3, fields.size, entry
          assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
          assert_equal 'test', fields['tag2']['stringValue'], entry
          assert_equal 5000, fields['data']['numberValue'], entry
        end
      end
    end
  end

  def test_timestamps_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      expected_ts = []
      emit_index = 0
      [Time.at(123_456.789), Time.at(0), Time.now].each do |ts|
        # Test the "native" fluentd timestamp as well as our nanosecond tags.
        d.emit({ 'message' => log_entry(emit_index) }, ts.to_f)
        # The native timestamp currently only supports second granularity
        # (fluentd issue #461), so strip nanoseconds from the expected value.
        expected_ts.push(Time.at(ts.tv_sec))
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
      verify_grpc_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
        if expected_ts[verify_index].tv_sec == 0
          # For an optional field with default values, protobuf omits the field
          # when deserialize it to json.
          assert_nil entry['metadata']['timestamp']['seconds']
        else
          assert_equal expected_ts[verify_index].tv_sec,
                       entry['metadata']['timestamp']['seconds'], entry
        end
        if expected_ts[verify_index].tv_nsec == 0
          # For an optional field with default values, protobuf omits the field
          # when deserialize it to json.
          assert_nil entry['metadata']['timestamp']['nanos']
        else
          assert_equal expected_ts[verify_index].tv_nsec,
                       entry['metadata']['timestamp']['nanos'], entry
        end
        verify_index += 1
      end
    end
  end

  def test_malformed_timestamp_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      # if timestamp is not a hash it is passed through to the struct payload.
      d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
        fields = entry['structPayload']['fields']
        assert_equal 2, fields.size, entry
        assert_equal 'not-a-hash', fields['timestamp']['stringValue'], entry
      end
    end
  end

  def test_severities_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      expected_severity = []
      emit_index = 0
      # Array of pairs of [parsed_severity, expected_severity]
      [%w(INFO INFO), %w(warn WARNING), %w(E ERROR), %w(BLAH DEFAULT),
       %w(105 DEBUG), ['', 'DEFAULT']].each do |sev|
        d.emit('message' => log_entry(emit_index), 'severity' => sev[0])
        expected_severity.push(sev[1])
        emit_index += 1
      end
      d.run
      verify_index = 0
      verify_grpc_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
        if expected_severity[verify_index] == 'DEFAULT'
          # For an optional field with default values, protobuf omits the field
          # when deserialize it to json.
          assert_nil entry['metadata']['severity'], entry
        else
          assert_equal expected_severity[verify_index],
                       entry['metadata']['severity'], entry
        end
        verify_index += 1
      end
    end
  end

  def test_label_map_without_field_present
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
      d.emit('message' => log_entry(0))
      d.run
      # No additional labels should be present
      verify_grpc_log_entries(1, COMPUTE_PARAMS)
    end
  end

  def test_label_map_with_field_present
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
      d.emit('message' => log_entry(0), 'label_field' => 'label_value')
      d.run
      # make a deep copy of COMPUTE_PARAMS and add the parsed label.
      params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
      params[:labels]['sent_label'] = 'label_value'
      verify_grpc_log_entries(1, params)
    end
  end

  def test_label_map_with_numeric_field_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
      d.emit('message' => log_entry(0), 'label_field' => 123_456_789)
      d.run
      # make a deep copy of COMPUTE_PARAMS and add the parsed label.
      params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
      params[:labels]['sent_label'] = '123456789'
      verify_grpc_log_entries(1, params)
    end
  end

  def test_label_map_with_hash_field_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      config = %(label_map { "label_field": "sent_label" })
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
      # I'm not sure this actually makes sense for a user to do, but make
      # sure that it works if they try it.
      d.emit('message' => log_entry(0),
             'label_field' => { 'k1' => 10, 'k2' => 'val' })
      d.run
      # make a deep copy of COMPUTE_PARAMS and add the parsed label.
      params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
      params[:labels]['sent_label'] = '{"k1"=>10, "k2"=>"val"}'
      verify_grpc_log_entries(1, params)
    end
  end

  def test_label_map_with_multiple_fields_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      config = %(
        label_map {
          "label1": "sent_label_1",
          "label_number_two": "foo.googleapis.com/bar",
          "label3": "label3"
        }
      )
      d = create_grpc_driver(USE_GRPC_CONFIG + config)
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
      verify_grpc_log_entries(1, params, 'structPayload') do |entry|
        fields = entry['structPayload']['fields']
        assert_equal 2, fields.size, entry
        assert_equal 'test log entry 0', fields['message']['stringValue'], entry
        assert_equal 'value4', fields['not_a_label']['stringValue'], entry
      end
    end
  end

  def test_multiple_logs_grpc
    setup_gce_metadata_stubs
    # Only test a few values because otherwise the test can take minutes.
    [2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
        verify_grpc_log_entries(n, COMPUTE_PARAMS)
      end
    end
  end

  def test_malformed_log_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      # if the entry is not a hash, the plugin should silently drop it.
      d.emit('a string is not a valid message')
      d.run
      assert @logs_sent.empty?
    end
  end

  def test_client_error_grpc
    setup_gce_metadata_stubs
    { 8 => 'ResourceExhausted',
      12 => 'Unimplemented',
      16 => 'Unauthenticated' }.each_with_index do |(code, message), index|
      setup_grpc_logging_stubs(true, code, message) do
        d = create_grpc_driver(USE_GRPC_CONFIG, 'test',
                               GRPCLoggingMockFailingService.rpc_stub_class)
        # The API Client should not retry this and the plugin should consume the
        # exception.
        d.emit('message' => log_entry(0))
        d.run
        assert_equal 1, @failed_attempts.size, "Index #{index} failed."
      end
    end
  end

  def test_server_error_grpc
    setup_gce_metadata_stubs
    { 1 => 'Cancelled',
      2 => 'Unknown',
      4 => 'DeadlineExceeded',
      13 => 'Internal',
      14 => 'Unavailable' }.each_with_index do |(code, message), index|
      setup_grpc_logging_stubs(true, code, message) do
        d = create_grpc_driver(USE_GRPC_CONFIG, 'test',
                               GRPCLoggingMockFailingService.rpc_stub_class)
        # The API client should retry this once, then throw an exception which
        # gets propagated through the plugin
        d.emit('message' => log_entry(0))
        exception_count = 0
        begin
          d.run
        rescue GRPC::Cancelled => error
          assert_equal "GRPC::#{message}", error.message
          exception_count += 1
        rescue GRPC::BadStatus => error
          assert_equal "#{code}:#{message}", error.message
          exception_count += 1
        end
        assert_equal 1, @failed_attempts.size, "Index #{index} failed."
        assert_equal 1, exception_count, "Index #{index} failed."
      end
    end
  end

  def test_one_managed_vm_log_grpc
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('message' => log_entry(0))
      d.run
      verify_grpc_log_entries(1, VMENGINE_PARAMS)
    end
  end

  def test_multiple_managed_vm_logs_grpc
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
        verify_grpc_log_entries(n, VMENGINE_PARAMS)
      end
    end
  end

  def test_one_container_log_metadata_from_plugin_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata(log_entry(0)))
      d.run
      verify_grpc_log_entries(1, CONTAINER_FROM_METADATA_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def test_multiple_container_logs_metadata_from_plugin_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(container_log_entry_with_metadata(log_entry(i))) }
        d.run
        verify_grpc_log_entries(n, CONTAINER_FROM_METADATA_PARAMS) do |entry|
          assert_equal CONTAINER_SECONDS_EPOCH, \
                       entry['metadata']['timestamp']['seconds'], entry
          assert_equal CONTAINER_NANOS, \
                       entry['metadata']['timestamp']['nanos'], entry
          assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
        end
      end
    end
  end

  def test_multiple_container_logs_metadata_from_tag_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(container_log_entry(log_entry(i))) }
        d.run
        verify_grpc_log_entries(n, CONTAINER_FROM_TAG_PARAMS) do |entry|
          assert_equal CONTAINER_SECONDS_EPOCH, \
                       entry['metadata']['timestamp']['seconds'], entry
          assert_equal CONTAINER_NANOS, \
                       entry['metadata']['timestamp']['nanos'], entry
          assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
        end
      end
    end
  end

  def test_one_container_log_metadata_from_tag_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0)))
      d.run
      verify_grpc_log_entries(1, CONTAINER_FROM_TAG_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def test_one_container_log_from_tag_stderr_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0), 'stderr'))
      d.run
      expected_params = CONTAINER_FROM_TAG_PARAMS.merge(
        labels: { "#{CONTAINER_SERVICE_NAME}/stream" => 'stderr' }
      ) { |_, oldval, newval| oldval.merge(newval) }
      verify_grpc_log_entries(1, expected_params) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal 'ERROR', entry['metadata']['severity'], entry
      end
    end
  end

  def test_struct_container_log_metadata_from_plugin_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                               '"tag2": "test", "data": ' \
                                               '5000, "severity": "WARNING"}'))
      d.run
      verify_grpc_log_entries(1, CONTAINER_FROM_METADATA_PARAMS,
                              'structPayload') do |entry|
        fields = entry['structPayload']['fields']
        assert_equal 3, fields.size, entry
        assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
        assert_equal 'test', fields['tag2']['stringValue'], entry
        assert_equal 5000, fields['data']['numberValue'], entry
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal 'WARNING', entry['metadata']['severity'], entry
      end
    end
  end

  def test_struct_container_log_metadata_from_tag_grpc
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                                 '"tag2": "test", "data": 5000, ' \
                                 '"severity": "W"}'))
      d.run
      verify_grpc_log_entries(1, CONTAINER_FROM_TAG_PARAMS,
                              'structPayload') do |entry|
        fields = entry['structPayload']['fields']
        assert_equal 3, fields.size, entry
        assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
        assert_equal 'test', fields['tag2']['stringValue'], entry
        assert_equal 5000, fields['data']['numberValue'], entry
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal 'WARNING', entry['metadata']['severity'], entry
      end
    end
  end

  def test_cloudfunctions_log_grpc
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver(USE_GRPC_CONFIG, CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
        verify_grpc_log_entries(n, CLOUDFUNCTIONS_PARAMS) do |entry|
          assert_equal 'DEBUG', entry['metadata']['severity'],
                       "Test with #{n} logs failed. \n#{entry}"
        end
      end
    end
  end

  def test_cloudfunctions_logs_text_not_matched_grpc
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver(USE_GRPC_CONFIG, CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(cloudfunctions_log_entry_text_not_matched(i)) }
        d.run
        verify_grpc_log_entries(
          n, CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS) do |entry|
          assert_equal 'INFO', entry['metadata']['severity'],
                       "Test with #{n} logs failed. \n#{entry}"
        end
      end
    end
  end

  def test_multiple_cloudfunctions_logs_tag_not_matched_grpc
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      setup_grpc_logging_stubs do
        d = create_grpc_driver(USE_GRPC_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
        i = 0
        params = CONTAINER_FROM_TAG_PARAMS
        verify_grpc_log_entries(n, params, '') do |entry|
          assert_equal '[D][2015-09-25T12:34:56.789Z][123-0] test log entry ' \
                       "#{i}", entry['textPayload'],
                       "Test with #{n} logs failed. \n#{entry}"
          i += 1
        end
      end
    end
  end

  def test_http_request_from_record_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('httpRequest' => HTTP_REQUEST_MESSAGE_GRPC)
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE_GRPC, entry['httpRequest'], entry
        assert_nil entry['structPayload']['fields']['httpRequest'], entry
      end
    end
  end

  def test_http_request_partial_from_record_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('httpRequest' => HTTP_REQUEST_MESSAGE_GRPC.merge(
        'otherKey' => 'value'))
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal HTTP_REQUEST_MESSAGE_GRPC, entry['httpRequest'], entry
        fields = entry['structPayload']['fields']['httpRequest']['structValue']
        other_key = fields['fields']['otherKey']['stringValue']
        assert_equal 'value', other_key, entry
      end
    end
  end

  def test_http_request_without_referer_from_record_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      message_without_referer = HTTP_REQUEST_MESSAGE_GRPC.reject do |key, _|
        key == 'referer'
      end
      d.emit('httpRequest' => message_without_referer)
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
        assert_equal message_without_referer, entry['httpRequest'], entry
        assert_nil entry['structPayload']['fields']['httpRequest'], entry
      end
    end
  end

  def test_http_request_when_not_hash_grpc
    setup_gce_metadata_stubs
    setup_grpc_logging_stubs do
      d = create_grpc_driver
      d.emit('httpRequest' => 'a_string')
      d.run
      verify_grpc_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
        value = entry['structPayload']['fields']['httpRequest']['stringValue']
        assert_equal 'a_string', value, entry
        assert_equal nil, entry['httpRequest'], entry
      end
    end
  end
end
