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

require 'helper'
require 'json'
require 'mocha/test_unit'
require 'webmock/test_unit'
require 'google/apis'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputTest < Test::Unit::TestCase
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

  HTTP_REQUEST_MESSAGE = {
    'requestMethod' => 'POST',
    'requestUrl' => 'http://example/',
    'requestSize' => 210,
    'status' => 200,
    'responseSize' => 65,
    'userAgent' => 'USER AGENT 1.0',
    'remoteIp' => '55.55.55.55',
    'referer' => 'http://referer/',
    'cacheHit' => false,
    'validatedWithOriginServer' => true
  }

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput, tag).configure(conf, use_v1_config: true)
  end

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

  def test_timestamps
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver
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
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal expected_ts[verify_index].tv_sec,
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal expected_ts[verify_index].tv_nsec,
                   entry['metadata']['timestamp']['nanos'], entry
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

  # All credentials errors resolve to a 401.
  def test_client_401
    setup_gce_metadata_stubs
    stub_request(:post, uri_for_log(COMPUTE_PARAMS))
      .to_return(status: 401, body: 'Unauthorized')
    d = create_driver
    d.emit('message' => log_entry(0))
    begin
      d.run
    rescue Google::Apis::AuthorizationError => error
      assert_equal 'Unauthorized', error.message
    end
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), times: 2)
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
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS)
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
      verify_log_entries(n, CONTAINER_FROM_METADATA_PARAMS)
    end
  end

  def test_one_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry(log_entry(0)))
    d.run
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS)
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
      verify_log_entries(n, CONTAINER_FROM_TAG_PARAMS)
    end
  end

  def test_struct_container_log_metadata_from_plugin
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                             '"tag2": "test", "data": 5000}'))
    d.run
    verify_log_entries(1, CONTAINER_FROM_METADATA_PARAMS,
                       'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
    end
  end

  def test_struct_container_log_metadata_from_tag
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
    d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                               '"tag2": "test", "data": 5000}'))
    d.run
    verify_log_entries(1, CONTAINER_FROM_TAG_PARAMS,
                       'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
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
    # Stub the root, used for platform detection
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Server' => 'EC2ws' })

    # Stub the identity document lookup made by the agent.
    stub_request(:get, 'http://169.254.169.254/latest/dynamic/' \
                 'instance-identity/document')
      .to_return(body: EC2_IDENTITY_DOCUMENT, status: 200,
                 headers: { 'Content-Length' => EC2_IDENTITY_DOCUMENT.length })
  end

  def setup_logging_stubs
    [COMPUTE_PARAMS, VMENGINE_PARAMS, CONTAINER_FROM_TAG_PARAMS,
     CONTAINER_FROM_METADATA_PARAMS, CLOUDFUNCTIONS_PARAMS, CUSTOM_PARAMS,
     EC2_PARAMS].each do |params|
      stub_request(:post, uri_for_log(params)).to_return do |request|
        @logs_sent << JSON.parse(request.body)
        { body: '' }
      end
    end
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
      stream: 'stdout',
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

  def container_log_entry(log)
    {
      log: log,
      stream: 'stdout'
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
  def verify_log_entries(n, params, payload_type = 'textPayload')
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
end
