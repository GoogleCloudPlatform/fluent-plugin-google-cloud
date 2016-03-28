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

require 'helper'
require 'json'
require 'mocha/test_unit'
require 'webmock/test_unit'
require 'logger'

class MyConfig
  # Use the GoogleUtil::MetadataMixin mixin, which is what is tested
  include Fluent::GoogleUtil::MetadataMixin

  attr_accessor :use_metadata_service
  attr_accessor :detect_subservice
  attr_accessor :ext

  def initialize(hash = nil)
    @use_metadata_service = true
    @detect_subservice = true
    hash.each { |k, v| instance_variable_set("@#{k}", v) } unless hash.nil?
    @log = Logger.new('/dev/null')
    @ext = detect_metadata(@use_metadata_service, @detect_subservice)
  end
end

class MyCredentials
  # Use the GoogleUtil::MetadataMixin mixin, which is what is tested
  include Fluent::GoogleUtil::CredentialsMixin

  attr_accessor :credentials

  def initialize(hash = nil)
    hash.each { |k, v| instance_variable_set("@#{k}", v) } unless hash.nil?
  end

  def authorize
    super
  end

  def project_id_from_credentials
    super
  end
end

# Unit tests for Google Cloud Logging plugin
class GoogleUtilMetadataTest < Test::Unit::TestCase
  def setup
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

  # Cloud Functions
  CLOUDFUNCTIONS_CLUSTER_NAME = 'cluster-2'
  CLOUDFUNCTIONS_REGION = 'us-central1'

  # Configuration files for various test scenarios
  NO_DETECT_SUBSERVICE_CONFIG = {
    'detect_subservice' => false
  }

  CUSTOM_METADATA_CONFIG = {
    'project_id' => "#{CUSTOM_PROJECT_ID}",
    'zone' => "#{CUSTOM_ZONE}",
    'vm_id' => "#{CUSTOM_VM_ID}",
    'vm_name' => "#{CUSTOM_HOSTNAME}"
  }

  CONFIG_MISSING_METADATA_PROJECT_ID = {
    'zone' => "#{CUSTOM_ZONE}",
    'vm_id' => "#{CUSTOM_VM_ID}",
    'vm_name' => "#{CUSTOM_HOSTNAME}"
  }

  CONFIG_MISSING_METADATA_VM_ID = {
    'project_id' => "#{CUSTOM_PROJECT_ID}",
    'zone' => "#{CUSTOM_ZONE}"
  }

  CONFIG_MISSING_METADATA_ZONE = {
    'project_id' => "#{CUSTOM_PROJECT_ID}",
    'vm_id' => "#{CUSTOM_VM_ID}",
    'vm_name' => "#{CUSTOM_HOSTNAME}"
  }

  CONFIG_EC2_PROJECT_ID = {
    'project_id' => "#{EC2_PROJECT_ID}"
  }

  CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID = {
    'project_id' => "#{EC2_PROJECT_ID}",
    'vm_id' => "#{CUSTOM_VM_ID}"
  }

  # Service configurations for various services
  COMPUTE_SERVICE_NAME = 'compute.googleapis.com'
  APPENGINE_SERVICE_NAME = 'appengine.googleapis.com'
  CONTAINER_SERVICE_NAME = 'container.googleapis.com'
  CLOUDFUNCTIONS_SERVICE_NAME = 'cloudfunctions.googleapis.com'
  EC2_SERVICE_NAME = 'ec2.amazonaws.com'

  def test_configure_invalid_metadata_missing_all_no_metadata_service
    setup_no_metadata_service_stubs
    d = MyConfig.new
    assert d.platform
    assert d.vm_name
    assert d.service_name
    # Everything else is unset
    assert d.project_id.nil?
    assert d.zone.nil?
    assert d.vm_id.nil?
    assert d.component.nil?
    # Secondary attributes are nil.
    assert d.ext.nil?
  end

  def test_configure_no_use_metadata_service
    config = { 'use_metadata_service' => false }
    d = MyConfig.new config
    assert d.platform
    assert d.vm_name
    assert d.service_name
    # Everything else is unset
    assert d.project_id.nil?
    assert d.zone.nil?
    assert d.vm_id.nil?
    assert d.component.nil?
    # Secondary attributes are nil.
    assert d.ext.nil?
  end

  def test_configure_invalid_metadata_missing_project_id_no_metadata_service
    setup_no_metadata_service_stubs
    d = MyConfig.new CONFIG_MISSING_METADATA_PROJECT_ID
    assert d.project_id.nil?
    assert d.ext.nil?
  end

  def test_configure_invalid_metadata_missing_zone_no_metadata_service
    setup_no_metadata_service_stubs
    d = MyConfig.new CONFIG_MISSING_METADATA_ZONE
    assert d.zone.nil?
    assert d.ext.nil?
  end

  def test_configure_invalid_metadata_missing_vm_id_no_metadata_service
    setup_no_metadata_service_stubs
    d = MyConfig.new CONFIG_MISSING_METADATA_VM_ID
    assert d.vm_id.nil?
    assert d.ext.nil?
  end

  def test_metadata_loading
    setup_gce_metadata_stubs
    d = MyConfig.new
    assert !d.ext.nil?
    assert_equal PROJECT_ID, d.project_id
    assert_equal ZONE, d.zone
    assert_equal VM_ID, d.vm_id
  end

  def test_managed_vm_metadata_loading
    setup_managed_vm_metadata_stubs
    d = MyConfig.new
    assert !d.ext.nil?
    assert_equal PROJECT_ID, d.project_id
    assert_equal ZONE, d.zone
    assert_equal VM_ID, d.vm_id
    assert_equal MANAGED_VM_BACKEND_NAME, d.ext.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.ext.gae_backend_version
  end

  def test_container_metadata_loading
    setup_container_metadata_stubs
    d = MyConfig.new
    assert !d.ext.nil?
    assert_equal PROJECT_ID, d.project_id
    assert_equal ZONE, d.zone
    assert_equal VM_ID, d.vm_id
    assert_equal CONTAINER_SERVICE_NAME, d.service_name
    assert_equal CONTAINER_CLUSTER_NAME, d.ext.kube_cluster_name
  end

  def test_cloudfunctions_metadata_loading
    setup_cloudfunctions_metadata_stubs
    d = MyConfig.new
    assert !d.ext.nil?
    assert_equal PROJECT_ID, d.project_id
    assert_equal ZONE, d.zone
    assert_equal VM_ID, d.vm_id
    assert_equal CLOUDFUNCTIONS_SERVICE_NAME, d.service_name
    assert_equal CLOUDFUNCTIONS_CLUSTER_NAME, d.ext.kube_cluster_name
    assert_equal CLOUDFUNCTIONS_REGION, d.ext.gcf_region
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false
    config = { 'use_metadata_service' => false }
    config = CUSTOM_METADATA_CONFIG.merge(config)
    d = MyConfig.new config
    assert_equal CUSTOM_PROJECT_ID, d.project_id
    assert_equal CUSTOM_ZONE, d.zone
    assert_equal CUSTOM_VM_ID, d.vm_id
    assert d.ext.nil?
  end

  def test_gce_used_when_detect_subservice_is_false
    setup_gce_metadata_stubs
    # This would cause the service to be container.googleapis.com if not for the
    # detect_subservice=false config.
    setup_container_metadata_stubs
    d = MyConfig.new NO_DETECT_SUBSERVICE_CONFIG
    assert_equal COMPUTE_SERVICE_NAME, d.service_name
    assert d.ext.nil?
  end

  def test_metadata_overrides_on_gce
    # In this case we are overriding all configured parameters so we should
    # see all "custom" values rather than the ones from the metadata server.
    setup_gce_metadata_stubs
    d = MyConfig.new CUSTOM_METADATA_CONFIG
    assert_equal CUSTOM_PROJECT_ID, d.project_id
    assert_equal CUSTOM_ZONE, d.zone
    assert_equal CUSTOM_VM_ID, d.vm_id
  end

  def test_metadata_partial_overrides_on_gce
    # Similar to above, but we are not overriding project_id in this config
    # so we should see the metadata value for project_id and "custom" otherwise.
    setup_gce_metadata_stubs
    d = MyConfig.new CONFIG_MISSING_METADATA_PROJECT_ID
    assert_equal PROJECT_ID, d.project_id
    assert_equal CUSTOM_ZONE, d.zone
    assert_equal CUSTOM_VM_ID, d.vm_id
  end

  def test_ec2_metadata_loading
    setup_ec2_metadata_stubs
    d = MyConfig.new CONFIG_EC2_PROJECT_ID
    assert_equal EC2_PROJECT_ID, d.project_id
    assert_equal EC2_PREFIXED_ZONE, d.zone
    assert_equal EC2_VM_ID, d.vm_id
  end

  def test_ec2_metadata_partial_override
    setup_ec2_metadata_stubs
    d = MyConfig.new CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID
    assert_equal EC2_PROJECT_ID, d.project_id
    assert_equal EC2_PREFIXED_ZONE, d.zone
    assert_equal CUSTOM_VM_ID, d.vm_id
  end

  def test_ec2_metadata_requires_project_id
    setup_ec2_metadata_stubs
    d = MyConfig.new
    assert d.project_id.nil?
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

  def _setup_gce_metadata_stubs
    # Stub the root, used for platform detection by the plugin and 'googleauth'.
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Metadata-Flavor' => 'Google' })

    # Create stubs for all the GCE metadata lookups the agent needs to make.
    stub_metadata_request('project/project-id', PROJECT_ID)
    stub_metadata_request('instance/zone', FULLY_QUALIFIED_ZONE)
    stub_metadata_request('instance/id', VM_ID)
  end

  def setup_gce_metadata_stubs
    _setup_gce_metadata_stubs
    stub_metadata_request('instance/attributes/',
                          "attribute1\nattribute2\nattribute3")
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

  def setup_managed_vm_metadata_stubs
    _setup_gce_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\ngae_backend_name\ngae_backend_version\nlast_attribute")
    stub_metadata_request('instance/attributes/gae_backend_name',
                          MANAGED_VM_BACKEND_NAME)
    stub_metadata_request('instance/attributes/gae_backend_version',
                          MANAGED_VM_BACKEND_VERSION)
  end

  def setup_container_metadata_stubs
    _setup_gce_metadata_stubs
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
    _setup_gce_metadata_stubs
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

  public

  # Name of the the Google cloud trace write scope.
  LOGGING_SCOPE = 'https://www.googleapis.com/auth/logging.write'

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
  INVALID_CREDENTIALS = {
    path: 'test/plugin/data/invalid_credentials.json',
    project_id: ''
  }

  # Method #0. No supplied credentials.

  # This should fail, but it does not because reasons. Primarily,
  # the underlying auth library likes to look in well-knonwn paths.
  def test_no_valid_config
    # Used by 'googleauth' to fetch the default service account credentials.
    stub_request(:any, %r{http://169.254.169.254/.*})
      .to_raise(Errno::EHOSTUNREACH)

    exception_count = 0
    d = MyCredentials.new
    begin
      d.get_credentials(LOGGING_SCOPE)
      d.authorize
    rescue StandardError
      # The error here could be any number of things, mainly coming down to a
      # Host Unreachable response code.
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  # Method #1. GCE service account credentials and/or
  # GOOGLE_APPLICATION_CREDENTIALS

  def test_get_gce_service_account_credentials
    setup_gce_auth_stubs
    d = MyCredentials.new
    d.get_credentials(LOGGING_SCOPE)
    d.authorize
    # gce account credentials do not support project_id_from_credentials,
    # however it is available via the metadata.
  end

  def test_get_application_default_json_credentials
    setup_auth_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = IAM_CREDENTIALS[:path]
    d = MyCredentials.new
    d.get_credentials(LOGGING_SCOPE)
    assert_equal IAM_CREDENTIALS[:project_id], d.project_id_from_credentials
    d.authorize
  end

  def test_get_application_default_invalid_json_credentials
    setup_auth_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = INVALID_CREDENTIALS[:path]
    d = MyCredentials.new
    exception_count = 0
    begin
      d.get_credentials(LOGGING_SCOPE)
      d.authorize
    rescue RuntimeError => error
      assert error.message.include? 'Unable to read the credential file'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  # Method #2

  def test_service_credentials_path
    setup_auth_stubs
    d = MyCredentials.new('service_credentials_path' => IAM_CREDENTIALS[:path])
    d.get_credentials(LOGGING_SCOPE)
    assert_equal IAM_CREDENTIALS[:project_id], d.project_id_from_credentials
    d.authorize
  end

  # TODO: Test Method 3: Client secrets & friends.

  private

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

    # Used for 'private_key' auth.
    stub_request(:post, 'https://accounts.google.com/o/oauth2/token')
      .with(body: hash_including(grant_type: AUTH_GRANT_TYPE))
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })
  end

  def setup_gce_auth_stubs
    # Stub the root, used for platform detection by the plugin and 'googleauth'.
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Metadata-Flavor' => 'Google' })

    # Used by 'googleauth' to fetch the default service account credentials.
    stub_request(:get, 'http://169.254.169.254/computeMetadata/v1/' \
                 'instance/service-accounts/default/token')
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })
    setup_auth_stubs
  end
end
