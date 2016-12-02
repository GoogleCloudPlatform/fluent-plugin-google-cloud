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

# Unit tests for Google Cloud Logging plugin
class GoogleCloudPluginBaseTest < Test::Unit::TestCase
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

  USE_GRPC_CONFIG = %(
    use_grpc true
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

  HTTP_REQUEST_MESSAGE_GRPC = {
    'requestMethod' => 'POST',
    'requestUrl' => 'http://example/',
    'requestSize' => 210,
    'status' => 200,
    'responseSize' => 65,
    'userAgent' => 'USER AGENT 1.0',
    'remoteIp' => '55.55.55.55',
    'referer' => 'http://referer/',
    'cacheHit' => true,
    'cacheValidatedWithOriginServer' => true
  }

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

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput, tag).configure(conf, use_v1_config: true)
  end

  # GRPC driver setup.
  GRPC_MOCK_HOST = 'localhost:56789'

  WriteLogEntriesRequest = Google::Logging::V1::WriteLogEntriesRequest
  WriteLogEntriesResponse = Google::Logging::V1::WriteLogEntriesResponse

  # Google Cloud Fluent output stub with grpc mock.
  class GoogleCloudOutputWithGRPCMock < Fluent::GoogleCloudOutput
    def initialize(grpc_stub)
      @grpc_stub = grpc_stub
    end

    def api_client
      ssl_creds = GRPC::Core::ChannelCredentials.new
      authentication = Google::Auth.get_application_default
      creds = GRPC::Core::CallCredentials.new(authentication.updater_proc)
      ssl_creds.compose(creds)

      # Here we have obtained the creds, but for the mock, we will leave the
      # channel insecure.
      @grpc_stub.new(GRPC_MOCK_HOST, :this_channel_is_insecure)
    end
  end

  def create_grpc_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test',
                         grpc_stub = GRPCLoggingMockService.rpc_stub_class)
    conf += USE_GRPC_CONFIG
    Fluent::Test::BufferedOutputTestDriver.new(
      GoogleCloudOutputWithGRPCMock.new(grpc_stub), tag).configure(
        conf, use_v1_config: true)
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
    yield
  end

  # GRPC logging mock that successfully logs the records.
  class GRPCLoggingMockService < Google::Logging::V1::LoggingService::Service
    def initialize(requests_received)
      super()
      @requests_received = requests_received
    end

    def write_log_entries(request, _call)
      @requests_received << request
      WriteLogEntriesResponse.new
    end

    def list_logs(_request, _call)
      fail "Method 'list_logs' should never be called."
    end

    def list_log_services(_request, _call)
      fail "Method 'list_log_services' should never be called."
    end

    def list_log_service_indexes(_request, _call)
      fail "Method 'list_log_service_indexes' should never be called."
    end

    def delete_log(_request, _call)
      fail "Method 'delete_log' should never be called."
    end
  end

  # GRPC logging mock that fails and returns server side or client side errors.
  class GRPCLoggingMockFailingService <
      Google::Logging::V1::LoggingService::Service
    # 'code_sent' and 'message_sent' are references of external variables. We
    #  will assert the values of them later. 'code_value' and 'message_value'
    #  are actual error code and message we expect this mock to return.
    def initialize(code, message, failed_attempts)
      @code = code
      @message = message
      @failed_attempts = failed_attempts
      super()
    end

    def write_log_entries(_request, _call)
      @failed_attempts << 1
      fail GRPC::BadStatus.new(@code, @message)
    end

    def list_logs(_request, _call)
      fail "Method 'list_logs' should never be called."
    end

    def list_log_services(_request, _call)
      fail "Method 'list_log_services' should never be called."
    end

    def list_log_service_indexes(_request, _call)
      fail "Method 'list_log_service_indexes' should never be called."
    end

    def delete_log(_request, _call)
      fail "Method 'delete_log' should never be called."
    end
  end

  def setup_grpc_logging_stubs(should_fail = false, code = 0, message = 'Ok')
    srv = GRPC::RpcServer.new
    @failed_attempts = []
    @requests_sent = []
    if should_fail
      grpc = GRPCLoggingMockFailingService.new(code, message, @failed_attempts)
    else
      grpc = GRPCLoggingMockService.new(@requests_sent)
    end
    srv.handle(grpc)
    srv.add_http2_port(GRPC_MOCK_HOST, :this_port_is_insecure)
    t = Thread.new { srv.run }
    srv.wait_till_running
    begin
      yield
    rescue Test::Unit::Failure, StandardError => e
      srv.stop
      t.join
      raise e
    end
    srv.stop
    t.join
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

  def underscore(camel_cased_word)
    camel_cased_word.to_s.gsub(/::/, '/')
      .gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
      .gsub(/([a-z\d])([A-Z])/, '\1_\2')
      .downcase
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_grpc_log_entries(n, params, payload_type = 'textPayload', &block)
    @requests_sent.each do |batch|
      @logs_sent << JSON.parse(batch.to_json)
    end
    verify_log_entries(n, params, payload_type, &block)
  end

  # Shared tests

  def verify_configure_service_account_application_default(create_driver_func)
    setup_gce_metadata_stubs
    d = create_driver_func.call
    assert_equal HOSTNAME, d.instance.vm_name
  end

  def verify_configure_service_account_private_key(create_driver_func)
    # Using out-of-date config method.
    setup_gce_metadata_stubs
    exception_count = 0
    begin
      create_driver_func.call(PRIVATE_KEY_CONFIG)
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Please remove configuration parameters'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def verify_configure_custom_metadata(create_driver_func)
    setup_no_metadata_service_stubs
    d = create_driver_func.call(CUSTOM_METADATA_CONFIG)
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
  end

  def verify_configure_invalid_metadata_missing_parts(create_driver_func)
    setup_no_metadata_service_stubs
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    { CONFIG_MISSING_METADATA_PROJECT_ID => ['project_id'],
      CONFIG_MISSING_METADATA_ZONE => ['zone'],
      CONFIG_MISSING_METADATA_VM_ID => ['vm_id'],
      CONFIG_MISSING_METADATA_ALL => %w(project_id zone vm_id)
    }.each_with_index do |(config, parts), index|
      exception_count = 0
      begin
        create_driver_func.call(config)
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

  def verify_metadata_loading(create_driver_func)
    setup_gce_metadata_stubs
    d = create_driver_func.call
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def verify_managed_vm_metadata_loading(create_driver_func)
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    d = create_driver_func.call
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal true, d.instance.running_on_managed_vm
    assert_equal MANAGED_VM_BACKEND_NAME, d.instance.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.instance.gae_backend_version
  end

  def verify_gce_metadata_does_not_load_when_use_metadata_service_is_false(
    create_driver_func)
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    d = create_driver_func.call(NO_METADATA_SERVICE_CONFIG +
                                CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def verify_gce_used_when_detect_subservice_is_false(create_driver_func)
    setup_gce_metadata_stubs
    # This would cause the service to be container.googleapis.com if not for the
    # detect_subservice=false config.
    setup_container_metadata_stubs
    d = create_driver_func.call(NO_DETECT_SUBSERVICE_CONFIG)
    d.run
    assert_equal COMPUTE_SERVICE_NAME, d.instance.service_name
  end

  def verify_metadata_overrides(create_driver_func)
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
      d = create_driver_func.call(config)
      d.run
      assert_equal parts[1], d.instance.project_id, "Index #{index} failed."
      assert_equal parts[2], d.instance.zone, "Index #{index} failed."
      assert_equal parts[3], d.instance.vm_id, "Index #{index} failed."
      assert_equal false, d.instance.running_on_managed_vm,
                   "Index #{index} failed."
    end
  end

  def verify_ec2_metadata_requires_project_id(create_driver_func)
    setup_ec2_metadata_stubs
    exception_count = 0
    Fluent::GoogleCloudOutput::CredentialsInfo.stubs(:project_id).returns(nil)
    begin
      create_driver_func.call
    rescue Fluent::ConfigError => error
      assert error.message.include? 'Unable to obtain metadata parameters:'
      assert error.message.include? 'project_id'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def verify_ec2_metadata_project_id_from_credentials(create_driver_func)
    setup_ec2_metadata_stubs
    [IAM_CREDENTIALS, LEGACY_CREDENTIALS].each do |creds|
      ENV['GOOGLE_APPLICATION_CREDENTIALS'] = creds[:path]
      d = create_driver_func.call
      d.run
      assert_equal creds[:project_id], d.instance.project_id
    end
  end

  def verify_one_log(setup_logging_stubs_func, create_driver_func,
                     verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS)
  end

  def verify_one_log_with_json_credentials(setup_logging_stubs_func,
                                           create_driver_func,
                                           verify_log_entries_func)
    setup_gce_metadata_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS)
  end

  def verify_one_log_with_invalid_json_credentials(setup_logging_stubs_func,
                                                   create_driver_func)
    setup_gce_metadata_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = INVALID_CREDENTIALS[:path]
    setup_logging_stubs_func.call do
      d = create_driver_func.call
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

  def verify_one_log_custom_metadata(setup_logging_stubs_func,
                                     create_driver_func,
                                     verify_log_entries_func)
    # don't set up any metadata stubs, so the test will fail if we try to
    # fetch metadata (and explicitly check this as well).
    Fluent::GoogleCloudOutput.any_instance.expects(:fetch_metadata).never
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_logging_stubs_func.call do
      d = create_driver_func.call(NO_METADATA_SERVICE_CONFIG +
        CUSTOM_METADATA_CONFIG)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries_func.call(1, CUSTOM_PARAMS)
  end

  def verify_one_log_ec2(setup_logging_stubs_func, create_driver_func,
                         verify_log_entries_func)
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    setup_ec2_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(CONFIG_EC2_PROJECT_ID)
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries_func.call(1, EC2_PARAMS)
  end

  def grpc_on?(create_driver_func)
    create_driver_func.name == :create_grpc_driver
  end

  def verify_struct_payload_log(setup_logging_stubs_func, create_driver_func,
                                verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000)
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
        fields = entry['structPayload']['fields']
        assert_equal 3, fields.size, entry
        assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
        assert_equal 'test', fields['tag2']['stringValue'], entry
        assert_equal 5000, fields['data']['numberValue'], entry
      else
        assert_equal 3, entry['structPayload'].size, entry
        assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
        assert_equal 'test', entry['structPayload']['tag2'], entry
        assert_equal 5000, entry['structPayload']['data'], entry
      end
    end
  end

  def verify_struct_payload_json_log(setup_logging_stubs_func,
                                     create_driver_func,
                                     verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
      d.emit('message' => 'notJSON ' + json_string)
      d.emit('message' => json_string)
      d.emit('message' => "\t" + json_string)
      d.emit('message' => '  ' + json_string)
      d.run
    end
    verify_log_entries_func.call(4, COMPUTE_PARAMS, '') do |entry|
      assert entry.key?('textPayload'), 'Entry did not have textPayload'
    end
  end

  def verify_struct_payload_json_container_log(setup_logging_stubs_func,
                                               create_driver_func,
                                               verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      json_string = '{"msg": "test log entry 0", "tag2": "test", "data": 5000}'
      d.emit(container_log_entry_with_metadata('notJSON' + json_string))
      d.emit(container_log_entry_with_metadata(json_string))
      d.emit(container_log_entry_with_metadata("  \r\n \t" + json_string))
      d.run
    end
    log_index = 0
    verify_log_entries_func.call(
      3, CONTAINER_FROM_METADATA_PARAMS, '') do |entry|
      log_index += 1
      if log_index == 1
        assert entry.key?('textPayload'), 'Entry did not have textPayload'
      else
        assert entry.key?('structPayload'), 'Entry did not have structPayload'
        if grpc_on?(create_driver_func)
          fields = entry['structPayload']['fields']
          assert_equal 3, fields.size, entry
          assert_equal 'test log entry 0', fields['msg']['stringValue'], entry
          assert_equal 'test', fields['tag2']['stringValue'], entry
          assert_equal 5000, fields['data']['numberValue'], entry
        else
          assert_equal 3, entry['structPayload'].size, entry
          assert_equal 'test log entry 0', entry['structPayload']['msg'], entry
          assert_equal 'test', entry['structPayload']['tag2'], entry
          assert_equal 5000, entry['structPayload']['data'], entry
        end
      end
    end
  end

  def verify_timestamps(stub_setup_func, create_driver_func,
                        verify_log_entries_func)
    setup_gce_metadata_stubs
    expected_ts = []
    emit_index = 0
    stub_setup_func.call do
      [Time.at(123_456.789), Time.at(0), Time.now].each do |ts|
        d = create_driver_func.call
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
    verify_log_entries_func.call(emit_index, COMPUTE_PARAMS) do |entry|
      if expected_ts[verify_index].tv_sec == 0 && grpc_on?(create_driver_func)
        # For an optional field with default values, protobuf omits the field
        # when deserialize it to json.
        assert_nil entry['metadata']['timestamp']['seconds']
      else
        assert_equal expected_ts[verify_index].tv_sec,
                     entry['metadata']['timestamp']['seconds'], entry
      end
      if expected_ts[verify_index].tv_nsec == 0 && grpc_on?(create_driver_func)
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

  def verify_malformed_timestamp(setup_logging_stubs_func, create_driver_func,
                                 verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      # if timestamp is not a hash it is passed through to the struct payload.
      d.emit('message' => log_entry(0), 'timestamp' => 'not-a-hash')
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
        fields = entry['structPayload']['fields']
        assert_equal 2, fields.size, entry
        assert_equal 'not-a-hash', fields['timestamp']['stringValue'], entry
      else
        assert_equal 2, entry['structPayload'].size, entry
        assert_equal 'not-a-hash', entry['structPayload']['timestamp'], entry
      end
    end
  end

  def verify_severities(setup_logging_stubs_func, create_driver_func,
                        verify_log_entries_func)
    setup_gce_metadata_stubs
    expected_severity = []
    emit_index = 0
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      # Array of pairs of [parsed_severity, expected_severity]
      [%w(INFO INFO), %w(warn WARNING), %w(E ERROR), %w(BLAH DEFAULT),
       %w(105 DEBUG), ['', 'DEFAULT']].each do |sev|
        d.emit('message' => log_entry(emit_index), 'severity' => sev[0])
        expected_severity.push(sev[1])
        emit_index += 1
      end
      d.run
    end
    verify_index = 0
    verify_log_entries_func.call(emit_index, COMPUTE_PARAMS) do |entry|
      if expected_severity[verify_index] == 'DEFAULT' \
        && grpc_on?(create_driver_func)
        # For an optional field with default values, protobuf omits the field
        # when deserialize it to json.
        assert_nil entry['metadata']['severity'], entry
      elsif expected_severity[verify_index] == 'DEBUG' \
        && !grpc_on?(create_driver_func)
        # For some reason we return '100' instead of 'DEFAULT' for the non-grpc
        # path. And the original test asserts this.
        # TODO(lingshi) figure out if this is a bug or expected behavior.
        assert_equal 100, entry['metadata']['severity'], entry
      else
        assert_equal expected_severity[verify_index],
                     entry['metadata']['severity'], entry
      end
      verify_index += 1
    end
  end

  def verify_label_map_without_field_present(setup_logging_stubs_func,
                                             create_driver_func,
                                             verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver_func.call(config)
      d.emit('message' => log_entry(0))
      d.run
      # No additional labels should be present
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS)
  end

  def verify_label_map_with_field_present(setup_logging_stubs_func,
                                          create_driver_func,
                                          verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver_func.call(config)
      d.emit('message' => log_entry(0), 'label_field' => 'label_value')
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = 'label_value'
    verify_log_entries_func.call(1, params)
  end

  def verify_label_map_with_numeric_field(setup_logging_stubs_func,
                                          create_driver_func,
                                          verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver_func.call(config)
      d.emit('message' => log_entry(0), 'label_field' => 123_456_789)
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '123456789'
    verify_log_entries_func.call(1, params)
  end

  def verify_label_map_with_hash_field(setup_logging_stubs_func,
                                       create_driver_func,
                                       verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      config = %(label_map { "label_field": "sent_label" })
      d = create_driver_func.call(config)
      # I'm not sure this actually makes sense for a user to do, but make
      # sure that it works if they try it.
      d.emit('message' => log_entry(0),
             'label_field' => { 'k1' => 10, 'k2' => 'val' })
      d.run
    end
    # make a deep copy of COMPUTE_PARAMS and add the parsed label.
    params = Marshal.load(Marshal.dump(COMPUTE_PARAMS))
    params[:labels]['sent_label'] = '{"k1"=>10, "k2"=>"val"}'
    verify_log_entries_func.call(1, params)
  end

  def verify_label_map_with_multiple_fields(setup_logging_stubs_func,
                                            create_driver_func,
                                            verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      config = %(
        label_map {
          "label1": "sent_label_1",
          "label_number_two": "foo.googleapis.com/bar",
          "label3": "label3"
        }
      )
      d = create_driver_func.call(config)
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
    verify_log_entries_func.call(1, params, 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
        fields = entry['structPayload']['fields']
        assert_equal 2, fields.size, entry
        assert_equal 'test log entry 0', fields['message']['stringValue'], entry
        assert_equal 'value4', fields['not_a_label']['stringValue'], entry
      else
        assert_equal 2, entry['structPayload'].size, entry
        assert_equal 'test log entry 0', entry['structPayload']['message'],
                     entry
        assert_equal 'value4', entry['structPayload']['not_a_label'], entry
      end
    end
  end

  def verify_multiple_logs(setup_logging_stubs_func, create_driver_func,
                           verify_log_entries_func)
    setup_gce_metadata_stubs
    # Only test a few values because otherwise the test can take minutes.
    [2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs_func.call do
        d = create_driver_func.call
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
      end
      verify_log_entries_func.call(n, COMPUTE_PARAMS)
    end
  end

  def verify_malformed_log(setup_logging_stubs_func, create_driver_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      # if the entry is not a hash, the plugin should silently drop it.
      d.emit('a string is not a valid message')
      d.run
    end
    assert @logs_sent.empty?
  end

  def verify_one_managed_vm_log(setup_logging_stubs_func, create_driver_func,
                                verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('message' => log_entry(0))
      d.run
    end
    verify_log_entries_func.call(1, VMENGINE_PARAMS)
  end

  def verify_multiple_managed_vm_logs(setup_logging_stubs_func,
                                      create_driver_func,
                                      verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs_func.call do
        d = create_driver_func.call
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit('message' => log_entry(i)) }
        d.run
      end
      verify_log_entries_func.call(n, VMENGINE_PARAMS)
    end
  end

  def verify_one_container_log_metadata_from_plugin(setup_logging_stubs_func,
                                                    create_driver_func,
                                                    verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata(log_entry(0)))
      d.run
    end
    verify_log_entries_func.call(1, CONTAINER_FROM_METADATA_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
    end
  end

  def verify_multiple_container_logs_metadata_from_plugin(
      setup_logging_stubs_func, create_driver_func, verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs_func.call do
        d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(container_log_entry_with_metadata(log_entry(i))) }
        d.run
      end
      verify_log_entries_func.call(n, CONTAINER_FROM_METADATA_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def verify_multiple_container_logs_metadata_from_tag(setup_logging_stubs_func,
                                                       create_driver_func,
                                                       verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    [2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs_func.call do
        d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(container_log_entry(log_entry(i))) }
        d.run
      end
      verify_log_entries_func.call(n, CONTAINER_FROM_TAG_PARAMS) do |entry|
        assert_equal CONTAINER_SECONDS_EPOCH, \
                     entry['metadata']['timestamp']['seconds'], entry
        assert_equal CONTAINER_NANOS, \
                     entry['metadata']['timestamp']['nanos'], entry
        assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
      end
    end
  end

  def verify_one_container_log_metadata_from_tag(setup_logging_stubs_func,
                                                 create_driver_func,
                                                 verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0)))
      d.run
    end
    verify_log_entries_func.call(1, CONTAINER_FROM_TAG_PARAMS) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal CONTAINER_SEVERITY, entry['metadata']['severity'], entry
    end
  end

  def verify_one_container_log_from_tag_stderr(setup_logging_stubs_func,
                                               create_driver_func,
                                               verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry(log_entry(0), 'stderr'))
      d.run
    end
    expected_params = CONTAINER_FROM_TAG_PARAMS.merge(
      labels: { "#{CONTAINER_SERVICE_NAME}/stream" => 'stderr' }
    ) { |_, oldval, newval| oldval.merge(newval) }
    verify_log_entries_func.call(1, expected_params) do |entry|
      assert_equal CONTAINER_SECONDS_EPOCH, \
                   entry['metadata']['timestamp']['seconds'], entry
      assert_equal CONTAINER_NANOS, \
                   entry['metadata']['timestamp']['nanos'], entry
      assert_equal 'ERROR', entry['metadata']['severity'], entry
    end
  end

  def verify_struct_container_log_metadata_from_plugin(setup_logging_stubs_func,
                                                       create_driver_func,
                                                       verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry_with_metadata('{"msg": "test log entry 0", ' \
                                               '"tag2": "test", "data": ' \
                                               '5000, "severity": "WARNING"}'))
      d.run
    end
    verify_log_entries_func.call(1, CONTAINER_FROM_METADATA_PARAMS,
                                 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
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
      else
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
  end

  def verify_struct_container_log_metadata_from_tag(setup_logging_stubs_func,
                                                    create_driver_func,
                                                    verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_container_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
      d.emit(container_log_entry('{"msg": "test log entry 0", ' \
                                 '"tag2": "test", "data": 5000, ' \
                                 '"severity": "W"}'))
      d.run
    end
    verify_log_entries_func.call(1, CONTAINER_FROM_TAG_PARAMS,
                                 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
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
      else
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
  end

  def verify_cloudfunctions_log(setup_logging_stubs_func, create_driver_func,
                                verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      setup_logging_stubs_func.call do
        d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG,
                                    CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        @logs_sent = []
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
      end
      verify_log_entries_func.call(n, CLOUDFUNCTIONS_PARAMS) do |entry|
        assert_equal 'DEBUG', entry['metadata']['severity'],
                     "Test with #{n} logs failed. \n#{entry}"
      end
    end
  end

  def verify_cloudfunctions_logs_text_not_matched(setup_logging_stubs_func,
                                                  create_driver_func,
                                                  verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs_func.call do
        d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG,
                                    CLOUDFUNCTIONS_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(cloudfunctions_log_entry_text_not_matched(i)) }
        d.run
      end
      verify_log_entries_func.call(
        n, CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS) do |entry|
        assert_equal 'INFO', entry['metadata']['severity'],
                     "Test with #{n} logs failed. \n#{entry}"
      end
    end
  end

  def verify_multiple_cloudfunctions_logs_tag_not_matched(
      setup_logging_stubs_func, create_driver_func, verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_cloudfunctions_metadata_stubs
    [1, 2, 3, 5, 11, 50].each do |n|
      @logs_sent = []
      setup_logging_stubs_func.call do
        d = create_driver_func.call(APPLICATION_DEFAULT_CONFIG, CONTAINER_TAG)
        # The test driver doesn't clear its buffer of entries after running, so
        # do it manually here.
        d.instance_variable_get('@entries').clear
        n.times { |i| d.emit(cloudfunctions_log_entry(i)) }
        d.run
      end
      i = 0
      verify_log_entries_func.call(n, CONTAINER_FROM_TAG_PARAMS, '') do |entry|
        assert_equal '[D][2015-09-25T12:34:56.789Z][123-0] test log entry ' \
                     "#{i}", entry['textPayload'],
                     "Test with #{n} logs failed. \n#{entry}"
        i += 1
      end
    end
  end

  def get_http_request_message(create_driver_func)
    if grpc_on?(create_driver_func)
      HTTP_REQUEST_MESSAGE_GRPC
    else
      HTTP_REQUEST_MESSAGE
    end
  end

  def verify_http_request_from_record(setup_logging_stubs_func,
                                      create_driver_func,
                                      verify_log_entries_func)
    setup_gce_metadata_stubs
    message = get_http_request_message(create_driver_func)
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('httpRequest' => message)
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal message, entry['httpRequest'], entry
      if grpc_on?(create_driver_func)
        assert_nil entry['structPayload']['fields']['httpRequest'], entry
      else
        assert_nil entry['structPayload']['httpRequest'], entry
      end
    end
  end

  def verify_http_request_partial_from_record(setup_logging_stubs_func,
                                              create_driver_func,
                                              verify_log_entries_func)
    setup_gce_metadata_stubs
    message = get_http_request_message(create_driver_func)
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('httpRequest' => message.merge(
        'otherKey' => 'value'))
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal message, entry['httpRequest'], entry
      if grpc_on?(create_driver_func)
        fields = entry['structPayload']['fields']['httpRequest']['structValue']
        other_key = fields['fields']['otherKey']['stringValue']
        assert_equal 'value', other_key, entry
      else
        assert_equal 'value', entry['structPayload']['httpRequest']['otherKey'],
                     entry
      end
    end
  end

  def verify_http_request_without_referer_from_record(setup_logging_stubs_func,
                                                      create_driver_func,
                                                      verify_log_entries_func)
    setup_gce_metadata_stubs
    message = get_http_request_message(create_driver_func)
    message_without_referer = message.reject do |key, _|
      key == 'referer'
    end
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('httpRequest' => message_without_referer)
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      if grpc_on?(create_driver_func)
        assert_equal message_without_referer, entry['httpRequest'], entry
        assert_nil entry['structPayload']['fields']['httpRequest'], entry
      else
        assert_equal message_without_referer.merge('referer' => nil),
                     entry['httpRequest'], entry
        assert_nil entry['structPayload']['httpRequest'], entry
      end
    end
  end

  def verify_http_request_when_not_hash(setup_logging_stubs_func,
                                        create_driver_func,
                                        verify_log_entries_func)
    setup_gce_metadata_stubs
    setup_logging_stubs_func.call do
      d = create_driver_func.call
      d.emit('httpRequest' => 'a_string')
      d.run
    end
    verify_log_entries_func.call(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      if grpc_on?(create_driver_func)
        value = entry['structPayload']['fields']['httpRequest']['stringValue']
      else
        value = entry['structPayload']['httpRequest']
      end
      assert_equal 'a_string', value, entry
      assert_equal nil, entry['httpRequest'], entry
    end
  end
end
