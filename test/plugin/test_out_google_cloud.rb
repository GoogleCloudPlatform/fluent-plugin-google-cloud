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
require 'webmock/test_unit'

class GoogleCloudOutputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup

    # Create stubs for all the GCE metadata lookups the agent needs to make.
    stub_metadata_request('project/numeric-project-id', PROJECT_ID)
    stub_metadata_request('instance/zone', FULLY_QUALIFIED_ZONE)
    stub_metadata_request('instance/id', VM_ID)
    stub_metadata_request('instance/attributes/',
                          "attribute1\nattribute2\nattribute3")

    stub_request(:post, 'https://accounts.google.com/o/oauth2/token').
      with(:body => hash_including({:grant_type => AUTH_GRANT_TYPE})).
      to_return(:body => "{\"access_token\": \"#{FAKE_AUTH_TOKEN}\"}",
                :status => 200,
                :headers => { 'Content-Length' => FAKE_AUTH_TOKEN })

    @logs_sent = []
    stub_request(:post, 'https://www.googleapis.com/logs/v1beta/projects/' +
                 PROJECT_ID + '/logs/test/entries').
      to_return { |request|
        @logs_sent << JSON.parse(request.body)
        { :body => '' }
    }
  end

  PROJECT_ID = '1234567890'
  ZONE = 'us-central1-b'
  FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  VM_ID = '9876543210'

  MANAGED_VM_BACKEND_NAME = 'default'
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'

  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
  FAKE_AUTH_TOKEN = 'abc123'

  COMPUTE_ENGINE_SERVICE_ACCOUNT_CONFIG = %[
  ]

  PRIVATE_KEY_CONFIG = %[
    auth_method private_key
    private_key_email 271661262351-ft99kc9kjro9rrihq3k2n3s2inbplu0q@developer.gserviceaccount.com
    private_key_path test/plugin/data/c31e573fd7f62ed495c9ca3821a5a85cb036dee1-privatekey.p12
  ]

  INVALID_CONFIG1 = %[
    auth_method private_key
    private_key_email nobody@example.com
  ]
  INVALID_CONFIG2 = %[
    auth_method private_key
    private_key_path /fake/path/to/key
  ]
  INVALID_CONFIG3 = %[
    auth_method service_account
  ]

  def create_driver(conf = PRIVATE_KEY_CONFIG)
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput).configure(conf)
  end

  def test_configure_service_account
    d = create_driver(COMPUTE_ENGINE_SERVICE_ACCOUNT_CONFIG)
    assert_equal 'compute_engine_service_account', d.instance.auth_method
  end

  def test_configure_service_account
    d = create_driver(PRIVATE_KEY_CONFIG)
    assert_equal 'private_key', d.instance.auth_method
  end

  def test_configure_invalid_configs
    begin
      d = create_driver(INVALID_CONFIG1)
      assert_false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'private_key_path'
    end
    begin
      d = create_driver(INVALID_CONFIG2)
      assert_false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'private_key_email'
    end
    begin
      d = create_driver(INVALID_CONFIG3)
      assert_false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'auth_method'
    end
  end

  def test_metadata_loading
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_managed_vm_metadata_loading
    set_up_managed_vm_metadata_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal true, d.instance.running_on_managed_vm
    assert_equal MANAGED_VM_BACKEND_NAME, d.instance.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.instance.gae_backend_version
  end

  def test_one_log
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    assert_equal 1, @logs_sent.length
    verify_log_entries(1)
  end

  def test_multiple_logs
    d = create_driver(PRIVATE_KEY_CONFIG)
    # Only test a few values because otherwise the test can take minutes.
    [2,3,5,11,50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get("@entries").clear
      @logs_sent = []
      n.times { |i| d.emit({ 'message' => log_entry(i) }) }
      d.run
      assert_equal n, @logs_sent.length
      verify_log_entries(n)
    end
  end

  def test_one_managed_vm_log
    set_up_managed_vm_metadata_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    assert_equal 1, @logs_sent.length
    verify_managed_vm_log_entries(1)
  end

  def test_multiple_managed_vm_logs
    set_up_managed_vm_metadata_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    [2,3,5,11,50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get("@entries").clear
      @logs_sent = []
      n.times { |i| d.emit({ 'message' => log_entry(i) }) }
      d.run
      assert_equal n, @logs_sent.length
      verify_managed_vm_log_entries(n)
    end
  end

  private

  def stub_metadata_request(metadata_path, response_body)
    stub_request(:get, 'http://metadata/computeMetadata/v1/' + metadata_path).
      to_return(:body => response_body, :status => 200,
                :headers => { 'Content-Length' => response_body.length })
  end

  def set_up_managed_vm_metadata_stubs
    stub_metadata_request(
      'instance/attributes/',
      "attribute1\ngae_backend_name\ngae_backend_version\nlast_attribute")
    stub_metadata_request('instance/attributes/gae_backend_name', 'default')
    stub_metadata_request('instance/attributes/gae_backend_version',
                          'guestbook2.0')
  end

  def log_entry(i)
    'test log entry ' + i.to_s
  end

  def verify_log_entries(n)
    n.times { |i|
      assert_equal "test log entry #{i}", @logs_sent[i]['logEntry']['details']
      assert_equal ZONE, @logs_sent[i]['metadata']['location']
      assert_equal VM_ID,
                   @logs_sent[i]['metadata']['computeEngine']['instanceId']
    }
  end

  def verify_managed_vm_log_entries(n)
    n.times { |i|
      assert_equal "test log entry #{i}", @logs_sent[i]['logEntry']['details']
      assert_equal ZONE, @logs_sent[i]['metadata']['location']
      assert_equal MANAGED_VM_BACKEND_NAME,
                   @logs_sent[i]['metadata']['appEngine']['moduleId']
      assert_equal MANAGED_VM_BACKEND_VERSION,
                   @logs_sent[i]['metadata']['appEngine']['versionId']
      assert_equal VM_ID,
                   @logs_sent[i]['metadata']['appEngine']['computeEngineVmId']
    }
  end
end
