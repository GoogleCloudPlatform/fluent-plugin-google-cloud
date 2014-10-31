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
    stub_metadata_request('project/project-id', PROJECT_ID)
    stub_metadata_request('instance/zone', FULLY_QUALIFIED_ZONE)
    stub_metadata_request('instance/id', VM_ID)
    stub_metadata_request('instance/attributes/',
                          "attribute1\nattribute2\nattribute3")

    stub_request(:post, 'https://accounts.google.com/o/oauth2/token').
      with(:body => hash_including({:grant_type => AUTH_GRANT_TYPE})).
      to_return(:body => "{\"access_token\": \"#{FAKE_AUTH_TOKEN}\"}",
                :status => 200,
                :headers => {'Content-Length' => FAKE_AUTH_TOKEN})

    @logs_sent = []
  end

  def setup_logging_stubs
    [COMPUTE_PARAMS, VMENGINE_PARAMS].each do |params|
      stub_request(:post, uri_for_log(params)).to_return do |request|
        @logs_sent << JSON.parse(request.body)
        {:body => ''}
      end
    end
  end

  PROJECT_ID = 'test-project-id'
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

  COMPUTE_SERVICE_NAME = 'compute.googleapis.com'
  APPENGINE_SERVICE_NAME = 'appengine.googleapis.com'

  COMPUTE_PARAMS = {
    'service_name' => COMPUTE_SERVICE_NAME,
    'log_name' => 'test',
    'labels' => {
      "#{COMPUTE_SERVICE_NAME}/resource_type" => ['strValue', 'instance'],
      "#{COMPUTE_SERVICE_NAME}/resource_id" => ['strValue', VM_ID]
    }
  }

  VMENGINE_PARAMS = {
    'service_name' => APPENGINE_SERVICE_NAME,
    'log_name' => "#{APPENGINE_SERVICE_NAME}%2Ftest",
    'labels' => {
      "#{APPENGINE_SERVICE_NAME}/module_id" => [
        'strValue', MANAGED_VM_BACKEND_NAME],
      "#{APPENGINE_SERVICE_NAME}/version_id" => [
        'strValue', MANAGED_VM_BACKEND_VERSION],
      "#{COMPUTE_SERVICE_NAME}/resource_type" => ['strValue', 'instance'],
      "#{COMPUTE_SERVICE_NAME}/resource_id" => ['strValue', VM_ID]
    }
  }

  def create_driver(conf=PRIVATE_KEY_CONFIG)
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
    setup_managed_vm_metadata_stubs
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
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_timestamps
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    expected_ts = []
    emit_index = 0
    [Time.at(123456.789), Time.at(0), Time.now].each do |ts|
      # Test both the "native" fluentd timestamp and timeNanos.
      d.emit({'message' => log_entry(emit_index)}, ts.to_f)
      # The native timestamp currently only supports second granularity
      # (fluentd issue #461), so strip nanoseconds from the expected value.
      expected_ts.push(Time.at(ts.tv_sec))
      emit_index += 1
      d.emit({'message' => log_entry(emit_index),
              'timeNanos' => ts.tv_sec * 1000000000 + ts.tv_nsec})
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

  def test_multiple_logs
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    # Only test a few values because otherwise the test can take minutes.
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit({'message' => log_entry(i)}) }
      d.run
      verify_log_entries(n, COMPUTE_PARAMS)
    end
  end

  def test_client_error
    # The API Client should not retry this and the plugin should consume
    # the exception.
    # Note that the current release of the API client (0.7-1) does actually
    # retry the request; this appears to be due to a bug which has since been
    # fixed but not released (see below).
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 400, :body => "Bad Request")
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    # TODO(salty) times should be 1, change it when the API client is fixed.
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), :times => 2)
  end

  def test_client_error_invalid_credentials
    # we expect this to retry once, then throw the error.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 401, :body => "Invalid Credentials")
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    exception_count = 0
    begin
      d.run
    rescue Google::APIClient::ClientError => error
      assert_equal 'Invalid Credentials', error.message
      exception_count += 1
    end
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), :times => 2)
    assert_equal 1, exception_count
  end

  def test_server_error
    # The API client should retry this once, then throw an exception which
    # gets propagated through the plugin.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 500, :body => "Server Error")
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    exception_count = 0
    begin
      d.run
    rescue Google::APIClient::ServerError => error
      assert_equal 'Server Error', error.message
      exception_count += 1
    end
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), :times => 2)
    assert_equal 1, exception_count
  end

  def test_one_managed_vm_log
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, VMENGINE_PARAMS)
  end

  def test_multiple_managed_vm_logs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    [2, 3, 5, 11, 50].each do |n|
      # The test driver doesn't clear its buffer of entries after running, so
      # do it manually here.
      d.instance_variable_get('@entries').clear
      @logs_sent = []
      n.times { |i| d.emit({'message' => log_entry(i)}) }
      d.run
      verify_log_entries(n, VMENGINE_PARAMS)
    end
  end

  private

  def uri_for_log(config)
    'https://www.googleapis.com/logging/v1beta/projects/' + PROJECT_ID +
        '/logs/' + config['log_name'] + '/entries:write'
  end

  def stub_metadata_request(metadata_path, response_body)
    stub_request(:get, 'http://metadata/computeMetadata/v1/' + metadata_path).
      to_return(:body => response_body, :status => 200,
                :headers => {'Content-Length' => response_body.length})
  end

  def setup_managed_vm_metadata_stubs
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

  def check_labels(entry, common_labels, expected_labels)
    # TODO(salty) test/handle overlap between common_labels and entry labels
    all_labels = common_labels.to_a + entry['metadata']['labels'].to_a
    all_labels.each do |label|
      key = label['key']
      assert expected_labels.has_key?(key), "Unexpected label #{label}"
      expected_type = expected_labels[key][0]
      expected_value = expected_labels[key][1]
      assert label.has_key?(expected_type),
          "Type mismatch - expected #{expected_type} in #{label}"
      assert_equal label[expected_type], expected_value,
          "Value mismatch - expected #{expected_value} in #{label}"
    end
    assert_equal expected_labels.length, all_labels.length,
        ("Expected #{expected_labels.length} labels, got " +
         "#{all_labels.length}")
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params)
    i = 0
    @logs_sent.each do |batch|
      batch['entries'].each do |entry|
        assert_equal "test log entry #{i}", entry['textPayload'], batch
        assert_equal ZONE, entry['metadata']['zone']
        assert_equal params['service_name'], entry['metadata']['serviceName']
        check_labels entry, batch['commonLabels'], params['labels']
        if (block_given?)
          yield(entry)
        end
        i += 1
        assert i <= n, "Number of entries #{i} exceeds expected number #{n}"
      end
    end
    assert i == n, "Number of entries #{i} does not match expected number #{n}"
  end
end
