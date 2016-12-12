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

# Unit tests for Google Cloud Logging plugin
module BaseTest
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

  # generic attributes
  HOSTNAME = Socket.gethostname

  # attributes used for the GCE metadata service
  PROJECT_ID = 'test-project-id'
  ZONE = 'us-central1-b'
  FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  VM_ID = '9876543210'

  # attributes used for custom (overridden) configs
  CUSTOM_PROJECT_ID = 'test-custom-project-id'
  CUSTOM_ZONE = 'us-custom-central1-b'
  CUSTOM_FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  CUSTOM_VM_ID = 'C9876543210'
  CUSTOM_HOSTNAME = 'custom.hostname.org'

  # attributes used for the EC2 metadata service
  EC2_PROJECT_ID = 'test-ec2-project-id'
  EC2_ZONE = 'us-west-2b'
  EC2_PREFIXED_ZONE = 'aws:' + EC2_ZONE
  EC2_VM_ID = 'i-81c16767'
  EC2_ACCOUNT_ID = '123456789012'

  # The formatting here matches the format used on the VM.
  EC2_IDENTITY_DOCUMENT = %({
    "accountId" : "#{EC2_ACCOUNT_ID}",
    "availabilityZone" : "#{EC2_ZONE}",
    "instanceId" : "#{EC2_VM_ID}"
  })

  # Managed VMs specific labels
  MANAGED_VM_BACKEND_NAME = 'default'
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'

  # Container Engine / Kubernetes specific labels
  CONTAINER_CLUSTER_NAME = 'cluster-1'
  CONTAINER_NAMESPACE_ID = '898268c8-4a36-11e5-9d81-42010af0194c'
  CONTAINER_NAMESPACE_NAME = 'kube-system'
  CONTAINER_POD_ID = 'cad3c3c4-4b9c-11e5-9d81-42010af0194c'
  CONTAINER_POD_NAME = 'redis-master-c0l82.foo.bar'
  CONTAINER_CONTAINER_NAME = 'redis'
  CONTAINER_LABEL_KEY = 'component'
  CONTAINER_LABEL_VALUE = 'redis-component'
  CONTAINER_STREAM = 'stdout'
  CONTAINER_SEVERITY = 'INFO'
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch
  CONTAINER_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'
  CONTAINER_SECONDS_EPOCH = 1_234_567_890
  CONTAINER_NANOS = 987_654_321

  # Cloud Functions specific labels
  CLOUDFUNCTIONS_FUNCTION_NAME = '$My_Function.Name-@1'
  CLOUDFUNCTIONS_REGION = 'us-central1'
  CLOUDFUNCTIONS_EXECUTION_ID = '123-0'
  CLOUDFUNCTIONS_CLUSTER_NAME = 'cluster-1'
  CLOUDFUNCTIONS_NAMESPACE_NAME = 'default'
  CLOUDFUNCTIONS_POD_NAME = 'd.dc.myu.uc.functionp.pc.name-a.a1.987-c0l82'
  CLOUDFUNCTIONS_CONTAINER_NAME = 'worker'

  # Parameters used for authentication
  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
  FAKE_AUTH_TOKEN = 'abc123'

  # Information about test credentials files.
  # path: Path to the credentials file.
  # project_id: ID of the project, which must correspond to the file contents.
  IAM_CREDENTIALS = {
    path: 'test/plugin/data/iam-credentials.json',
    project_id: 'fluent-test-project'
  }
  LEGACY_CREDENTIALS = {
    path: 'test/plugin/data/credentials.json',
    project_id: '847859579879'
  }
  INVALID_CREDENTIALS = {
    path: 'test/plugin/data/invalid_credentials.json',
    project_id: ''
  }

  # Configuration files for various test scenarios
  APPLICATION_DEFAULT_CONFIG = %(
  )

  # rubocop:disable Metrics/LineLength
  PRIVATE_KEY_CONFIG = %(
     auth_method private_key
     private_key_email 271661262351-ft99kc9kjro9rrihq3k2n3s2inbplu0q@developer.gserviceaccount.com
     private_key_path test/plugin/data/c31e573fd7f62ed495c9ca3821a5a85cb036dee1-privatekey.p12
  )
  # rubocop:enable Metrics/LineLength

  NO_METADATA_SERVICE_CONFIG = %(
    use_metadata_service false
  )

  NO_DETECT_SUBSERVICE_CONFIG = %(
    detect_subservice false
  )

  CUSTOM_METADATA_CONFIG = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
    vm_name #{CUSTOM_HOSTNAME}
  )

  CONFIG_MISSING_METADATA_PROJECT_ID = %(
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
  )
  CONFIG_MISSING_METADATA_ZONE = %(
    project_id #{CUSTOM_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  )
  CONFIG_MISSING_METADATA_VM_ID = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
  )
  CONFIG_MISSING_METADATA_ALL = %(
  )

  CONFIG_EC2_PROJECT_ID = %(
    project_id #{EC2_PROJECT_ID}
  )

  CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID = %(
    project_id #{EC2_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  )

  # Service configurations for various services
  COMPUTE_SERVICE_NAME = 'compute.googleapis.com'
  APPENGINE_SERVICE_NAME = 'appengine.googleapis.com'
  CONTAINER_SERVICE_NAME = 'container.googleapis.com'
  CLOUDFUNCTIONS_SERVICE_NAME = 'cloudfunctions.googleapis.com'
  EC2_SERVICE_NAME = 'ec2.amazonaws.com'

  COMPUTE_PARAMS = {
    service_name: COMPUTE_SERVICE_NAME,
    log_name: 'test',
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  VMENGINE_PARAMS = {
    service_name: APPENGINE_SERVICE_NAME,
    log_name: "#{APPENGINE_SERVICE_NAME}%2Ftest",
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      "#{APPENGINE_SERVICE_NAME}/module_id" => MANAGED_VM_BACKEND_NAME,
      "#{APPENGINE_SERVICE_NAME}/version_id" => MANAGED_VM_BACKEND_VERSION,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  CONTAINER_TAG = "kubernetes.#{CONTAINER_POD_NAME}_" \
                  "#{CONTAINER_NAMESPACE_NAME}_#{CONTAINER_CONTAINER_NAME}"

  CONTAINER_FROM_METADATA_PARAMS = {
    service_name: CONTAINER_SERVICE_NAME,
    log_name: CONTAINER_CONTAINER_NAME,
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      "#{CONTAINER_SERVICE_NAME}/instance_id" => VM_ID,
      "#{CONTAINER_SERVICE_NAME}/cluster_name" => CONTAINER_CLUSTER_NAME,
      "#{CONTAINER_SERVICE_NAME}/namespace_name" => CONTAINER_NAMESPACE_NAME,
      "#{CONTAINER_SERVICE_NAME}/namespace_id" => CONTAINER_NAMESPACE_ID,
      "#{CONTAINER_SERVICE_NAME}/pod_name" => CONTAINER_POD_NAME,
      "#{CONTAINER_SERVICE_NAME}/pod_id" => CONTAINER_POD_ID,
      "#{CONTAINER_SERVICE_NAME}/container_name" => CONTAINER_CONTAINER_NAME,
      "#{CONTAINER_SERVICE_NAME}/stream" => CONTAINER_STREAM,
      "label/#{CONTAINER_LABEL_KEY}" => CONTAINER_LABEL_VALUE,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  # Almost the same as from metadata, but missing namespace_id and pod_id.
  CONTAINER_FROM_TAG_PARAMS = {
    service_name: CONTAINER_SERVICE_NAME,
    log_name: CONTAINER_CONTAINER_NAME,
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      "#{CONTAINER_SERVICE_NAME}/instance_id" => VM_ID,
      "#{CONTAINER_SERVICE_NAME}/cluster_name" => CONTAINER_CLUSTER_NAME,
      "#{CONTAINER_SERVICE_NAME}/namespace_name" => CONTAINER_NAMESPACE_NAME,
      "#{CONTAINER_SERVICE_NAME}/pod_name" => CONTAINER_POD_NAME,
      "#{CONTAINER_SERVICE_NAME}/container_name" => CONTAINER_CONTAINER_NAME,
      "#{CONTAINER_SERVICE_NAME}/stream" => CONTAINER_STREAM,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  CLOUDFUNCTIONS_TAG = "kubernetes.#{CLOUDFUNCTIONS_POD_NAME}_" \
                        "#{CLOUDFUNCTIONS_NAMESPACE_NAME}_" \
                        "#{CLOUDFUNCTIONS_CONTAINER_NAME}"

  CLOUDFUNCTIONS_PARAMS = {
    service_name: CLOUDFUNCTIONS_SERVICE_NAME,
    log_name: 'cloud-functions',
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      'execution_id' => CLOUDFUNCTIONS_EXECUTION_ID,
      "#{CLOUDFUNCTIONS_SERVICE_NAME}/function_name" =>
        CLOUDFUNCTIONS_FUNCTION_NAME,
      "#{CLOUDFUNCTIONS_SERVICE_NAME}/region" => CLOUDFUNCTIONS_REGION,
      "#{CONTAINER_SERVICE_NAME}/instance_id" => VM_ID,
      "#{CONTAINER_SERVICE_NAME}/cluster_name" => CLOUDFUNCTIONS_CLUSTER_NAME,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS = {
    service_name: CLOUDFUNCTIONS_SERVICE_NAME,
    log_name: 'cloud-functions',
    project_id: PROJECT_ID,
    zone: ZONE,
    labels: {
      "#{CLOUDFUNCTIONS_SERVICE_NAME}/function_name" =>
        CLOUDFUNCTIONS_FUNCTION_NAME,
      "#{CLOUDFUNCTIONS_SERVICE_NAME}/region" => CLOUDFUNCTIONS_REGION,
      "#{CONTAINER_SERVICE_NAME}/instance_id" => VM_ID,
      "#{CONTAINER_SERVICE_NAME}/cluster_name" => CLOUDFUNCTIONS_CLUSTER_NAME,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

  CUSTOM_PARAMS = {
    service_name: COMPUTE_SERVICE_NAME,
    log_name: 'test',
    project_id: CUSTOM_PROJECT_ID,
    zone: CUSTOM_ZONE,
    labels: {
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => CUSTOM_VM_ID,
      "#{COMPUTE_SERVICE_NAME}/resource_name" => CUSTOM_HOSTNAME
    }
  }

  EC2_PARAMS = {
    service_name: EC2_SERVICE_NAME,
    log_name: 'test',
    project_id: EC2_PROJECT_ID,
    zone: EC2_PREFIXED_ZONE,
    labels: {
      "#{EC2_SERVICE_NAME}/resource_type" => 'instance',
      "#{EC2_SERVICE_NAME}/resource_id" => EC2_VM_ID,
      "#{EC2_SERVICE_NAME}/account_id" => EC2_ACCOUNT_ID,
      "#{EC2_SERVICE_NAME}/resource_name" => HOSTNAME
    }
  }

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
    # This would cause the service to be container.googleapis.com if not for the
    # detect_subservice=false config.
    setup_container_metadata_stubs
    d = create_driver(NO_DETECT_SUBSERVICE_CONFIG)
    d.run
    assert_equal COMPUTE_SERVICE_NAME, d.instance.service_name
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

  def test_struct_payload_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
    end
  end

  def test_struct_payload_json_log
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

  def test_struct_payload_json_container_log
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
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
        assert entry.key?('structPayload'), 'Entry did not have structPayload'
        fields = get_fields(entry['structPayload'])
        assert_equal 3, fields.size, entry
        assert_equal 'test log entry 0', get_string(fields['msg']), entry
        assert_equal 'test', get_string(fields['tag2']), entry
        assert_equal 5000, get_number(fields['data']), entry
      end
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
        d.run
      end
    end
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal_with_default entry['metadata']['timestamp']['seconds'],
                                expected_ts[verify_index].tv_sec, 0, entry
      assert_equal_with_default entry['metadata']['timestamp']['nanos'],
                                expected_ts[verify_index].tv_nsec, 0, entry do
        # Fluentd v0.14 onwards supports nanosecond timestamp values.
        # Added in 600 ns delta to avoid flaky tests introduced
        # due to rounding error in double-precision floating-point numbers
        # (to account for the missing 9 bits of precision ~ 512 ns).
        # See http://wikipedia.org/wiki/Double-precision_floating-point_format
        assert_in_delta expected_ts[verify_index].tv_nsec,
                        entry['metadata']['timestamp']['nanos'], 600, entry
      end
      verify_index += 1
    end
  end

  def test_malformed_timestamp
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      # if timestamp is not a hash it is passed through to the struct payload.
      d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
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
      # not_a_label passes through to the struct payload
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
    verify_log_entries(1, params, 'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
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
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
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
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0)))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
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
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                               '"tag2": "test", "data": ' \
                                               '5000, "severity": "WARNING"}'))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS,
                       'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
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
    setup_logging_stubs do
      d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                                 '"tag2": "test", "data": 5000, ' \
                                 '"severity": "W"}'))
      d.run
    end
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS,
                       'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
      assert_equal 3, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test', get_string(fields['tag2']), entry
      assert_equal 5000, get_number(fields['data']), entry
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal 'WARNING', entry['metadata']['severity'], entry
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
        assert_equal 'DEBUG', entry['metadata']['severity'],
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
        assert_equal 'INFO', entry['metadata']['severity'],
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
      d.emit('httpRequest' => http_request_message)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal http_request_message, entry['httpRequest'], entry
      assert_nil get_fields(entry['structPayload'])['httpRequest'], entry
    end
  end

  def test_http_request_partial_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => http_request_message.merge(
        'otherKey' => 'value'))
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal http_request_message, entry['httpRequest'], entry
      fields = get_fields(entry['structPayload'])
      request = get_fields(get_struct(fields['httpRequest']))
      assert_equal 'value', get_string(request['otherKey']), entry
    end
  end

  def test_http_request_without_referer_from_record
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => http_request_message_without_referer)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal http_request_message_without_referer, entry['httpRequest'],
                   entry
      assert_nil get_fields(entry['structPayload'])['httpRequest'], entry
    end
  end

  def test_http_request_when_not_hash
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => 'a_string')
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      fields = get_fields(entry['structPayload'])
      assert_equal 'a_string', get_string(fields['httpRequest']), entry
      assert_nil entry['httpRequest'], entry
    end
  end

  private

  def uri_for_log(params)
    'https://logging.googleapis.com/v1beta3/projects/' + params[:project_id] +
      '/logs/' + params[:log_name] + '/entries:write'
  end

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

  def container_log_entry_with_metadata(log)
    {
      log: log,
      stream: CONTAINER_STREAM,
      time: CONTAINER_TIMESTAMP,
      kubernetes: {
        namespace_id: CONTAINER_NAMESPACE_ID,
        namespace_name: CONTAINER_NAMESPACE_NAME,
        pod_id: CONTAINER_POD_ID,
        pod_name: CONTAINER_POD_NAME,
        container_name: CONTAINER_CONTAINER_NAME,
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

  def log_entry(i)
    'test log entry ' + i.to_s
  end

  def check_labels(entry, common_labels, expected_labels)
    # TODO(salty) test/handle overlap between common_labels and entry labels
    all_labels ||= common_labels
    all_labels.merge!(entry['metadata']['labels'] || {})
    all_labels.each do |key, value|
      assert value.is_a?(String), "Value #{value} for label #{key} " \
        'is not a string: ' + value.class.name
      assert expected_labels.key?(key), "Unexpected label #{key} => #{value}"
      assert_equal expected_labels[key], value, 'Value mismatch - expected ' \
        "#{expected_labels[key]} in #{key} => #{value}"
    end
    assert_equal expected_labels.length, all_labels.length, 'Expected ' \
      "#{expected_labels.length} labels, got #{all_labels.length}"
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_json_log_entries(n, params, payload_type = 'textPayload')
    i = 0
    @logs_sent.each do |batch|
      batch['entries'].each do |entry|
        unless payload_type.empty?
          assert entry.key?(payload_type), 'Entry did not contain expected ' \
            "#{payload_type} key: " + entry.to_s
          # Check the payload for textPayload, otherwise it's up to the caller.
          if payload_type == 'textPayload'
            assert_equal "test log entry #{i}", entry['textPayload'], batch
          end
        end

        assert_equal params[:zone], entry['metadata']['zone']
        assert_equal params[:service_name], entry['metadata']['serviceName']
        check_labels entry, batch['commonLabels'], params[:labels]
        yield(entry) if block_given?
        i += 1
        assert i <= n, "Number of entries #{i} exceeds expected number #{n}"
      end
    end
    assert i == n, "Number of entries #{i} does not match expected number #{n}"
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

  # A wrapper around the constant HTTP_REQUEST_MESSAGE, so the definition can be
  # skipped in the shared module here and defined in the test class later.
  def http_request_message
    _undefined
  end

  # A wrapper around the constant HTTP_REQUEST_MESSAGE_WITHOUT_REFERER, so the
  # definition can be skipped in the shared module and defined in the test
  # classes later.
  def http_request_message_without_referer
    _undefined
  end

  # Get the fields of the struct payload.
  def get_fields(_struct_payload)
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

  def _undefined
    fail "Method #{__callee__} is unimplemented and needs to be overridden."
  end
end
