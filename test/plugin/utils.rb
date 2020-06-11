# Copyright 2020 Google Inc. All rights reserved.
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

require_relative 'constants'

require 'prometheus/client'
require 'webmock/test_unit'

module Utils
  include Constants

  def delete_env_vars
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

  def setup_auth_stubs(base_url)
    # Used when loading credentials from a JSON file.
    stub_request(:post, base_url)
      .with(body: hash_including(grant_type: AUTH_GRANT_TYPE))
      .to_return(body: %({"access_token": "#{FAKE_AUTH_TOKEN}"}),
                 status: 200,
                 headers: { 'Content-Length' => FAKE_AUTH_TOKEN.length,
                            'Content-Type' => 'application/json' })

    stub_request(:post, base_url)
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
end
