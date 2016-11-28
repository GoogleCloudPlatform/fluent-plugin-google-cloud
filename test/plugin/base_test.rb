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

  private

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
    'referer' => 'http://referer/'
  }

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

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput, tag).configure(conf, use_v1_config: true)
  end

  # GRPC driver setup.
  GRPC_MOCK_HOST = 'localhost:56789'

  WriteLogEntriesRequest = Google::Logging::V1::WriteLogEntriesRequest
  WriteLogEntriesResponse = Google::Logging::V1::WriteLogEntriesResponse

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

  def create_grpc_driver(conf = USE_GRPC_CONFIG, tag = 'test',
                         grpc_stub = GRPCLoggingMockService.rpc_stub_class)
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
  end

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
end
