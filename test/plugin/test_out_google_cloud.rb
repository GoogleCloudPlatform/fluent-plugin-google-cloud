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
    ENV.delete('GOOGLE_APPLICATION_CREDENTIALS')
    setup_auth_stubs
    @logs_sent = []
  end

  PROJECT_ID = 'test-project-id'
  ZONE = 'us-central1-b'
  FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  VM_ID = '9876543210'

  CUSTOM_PROJECT_ID = 'test-custom-project-id'
  CUSTOM_ZONE = 'us-custom-central1-b'
  CUSTOM_FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  CUSTOM_VM_ID = 'C9876543210'

  MANAGED_VM_BACKEND_NAME = 'default'
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'

  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
  FAKE_AUTH_TOKEN = 'abc123'

  APPLICATION_DEFAULT_CONFIG = %[
  ]

  PRIVATE_KEY_CONFIG = %[
    auth_method private_key
    private_key_email 271661262351-ft99kc9kjro9rrihq3k2n3s2inbplu0q@developer.gserviceaccount.com
    private_key_path test/plugin/data/c31e573fd7f62ed495c9ca3821a5a85cb036dee1-privatekey.p12
  ]

  CUSTOM_METADATA_CONFIG = %[
    fetch_gce_metadata false
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
  ]

  INVALID_CONFIG_MISSING_PRIVATE_KEY_PATH = %[
    auth_method private_key
    private_key_email nobody@example.com
  ]
  INVALID_CONFIG_MISSING_PRIVATE_KEY_EMAIL = %[
    auth_method private_key
    private_key_path /fake/path/to/key
  ]
  INVALID_CONFIG_MISSING_METADATA_VM_ID = %[
    fetch_gce_metadata false
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
  ]

  COMPUTE_SERVICE_NAME = 'compute.googleapis.com'
  APPENGINE_SERVICE_NAME = 'appengine.googleapis.com'

  COMPUTE_PARAMS = {
    'service_name' => COMPUTE_SERVICE_NAME,
    'log_name' => 'test',
    'project_id' => PROJECT_ID,
    'zone' => ZONE,
    'labels' => {
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID
    }
  }

  VMENGINE_PARAMS = {
    'service_name' => APPENGINE_SERVICE_NAME,
    'log_name' => "#{APPENGINE_SERVICE_NAME}%2Ftest",
    'project_id' => PROJECT_ID,
    'zone' => ZONE,
    'labels' => {
      "#{APPENGINE_SERVICE_NAME}/module_id" => MANAGED_VM_BACKEND_NAME,
      "#{APPENGINE_SERVICE_NAME}/version_id" => MANAGED_VM_BACKEND_VERSION,
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => VM_ID
    }
  }

  CUSTOM_PARAMS = {
    'service_name' => COMPUTE_SERVICE_NAME,
    'log_name' => 'test',
    'project_id' => CUSTOM_PROJECT_ID,
    'zone' => CUSTOM_ZONE,
    'labels' => {
      "#{COMPUTE_SERVICE_NAME}/resource_type" => 'instance',
      "#{COMPUTE_SERVICE_NAME}/resource_id" => CUSTOM_VM_ID
    }
  }

  def create_driver(conf=APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::BufferedOutputTestDriver.new(
        Fluent::GoogleCloudOutput).configure(conf)
  end

  def test_configure_service_account_application_default
    setup_gce_metadata_stubs
    d = create_driver(APPLICATION_DEFAULT_CONFIG)
    assert d.instance.auth_method.nil?
  end

  def test_configure_service_account_private_key
    setup_gce_metadata_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    assert_equal 'private_key', d.instance.auth_method
  end

  def test_configure_custom_metadata
    d = create_driver(CUSTOM_METADATA_CONFIG)
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
  end

  def test_configure_invalid_configs
    setup_gce_metadata_stubs
    begin
      d = create_driver(INVALID_CONFIG_MISSING_PRIVATE_KEY_PATH)
      assert false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'private_key_path'
    end
    begin
      d = create_driver(INVALID_CONFIG_MISSING_PRIVATE_KEY_EMAIL)
      assert false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'private_key_email'
    end
    begin
      d = create_driver(INVALID_CONFIG_MISSING_METADATA_VM_ID)
      assert false
    rescue Fluent::ConfigError => error
      assert error.message.include? 'fetch_gce_metadata'
    end
  end

  def test_metadata_loading
    setup_gce_metadata_stubs
    d = create_driver()
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_managed_vm_metadata_loading
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    d = create_driver()
    d.run
    assert_equal PROJECT_ID, d.instance.project_id
    assert_equal ZONE, d.instance.zone
    assert_equal VM_ID, d.instance.vm_id
    assert_equal true, d.instance.running_on_managed_vm
    assert_equal MANAGED_VM_BACKEND_NAME, d.instance.gae_backend_name
    assert_equal MANAGED_VM_BACKEND_VERSION, d.instance.gae_backend_version
  end

  def test_gce_metadata_does_not_load_when_fetch_gce_metadata_is_false
    d = create_driver(CUSTOM_METADATA_CONFIG)
    d.run
    assert_equal CUSTOM_PROJECT_ID, d.instance.project_id
    assert_equal CUSTOM_ZONE, d.instance.zone
    assert_equal CUSTOM_VM_ID, d.instance.vm_id
    assert_equal false, d.instance.running_on_managed_vm
  end

  def test_one_log
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_json_credentials
    setup_gce_metadata_stubs
    setup_logging_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = 'test/plugin/data/credentials.json'
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_with_invalid_json_credentials
    setup_gce_metadata_stubs
    setup_logging_stubs
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = 'test/plugin/data/invalid_credentials.json'
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    exception_count = 0
    begin
      d.run
    rescue RuntimeError => error
      assert error.message.include? 'Unable to read the credential file'
      exception_count += 1
    end
    assert_equal 1, exception_count
  end

  def test_one_log_private_key
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver(PRIVATE_KEY_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, COMPUTE_PARAMS)
  end

  def test_one_log_custom_metadata
    ENV['GOOGLE_APPLICATION_CREDENTIALS'] = 'test/plugin/data/credentials.json'
    setup_logging_stubs
    d = create_driver(CUSTOM_METADATA_CONFIG)
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, CUSTOM_PARAMS)
  end

  def test_struct_payload_log
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver()
    d.emit({'msg' => log_entry(0), 'tag2' => 'test', 'data' => 5000})
    d.run
    verify_log_entries(1, COMPUTE_PARAMS, 'structPayload') do |entry|
      assert_equal 3, entry['structPayload'].size, entry
      assert_equal "test log entry 0", entry['structPayload']['msg'], entry
      assert_equal 'test', entry['structPayload']['tag2'], entry
      assert_equal 5000, entry['structPayload']['data'], entry
    end
  end

  def test_timestamps
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver()
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

  def test_severities
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver()
    expected_severity = []
    emit_index = 0
    # Array of pairs of [parsed_severity, expected_severity]
    [['INFO', 'INFO'], ['warn', 'WARNING'], ['E', 'ERROR'],
     ['BLAH', 'DEFAULT'], ['105', 100], ['', 'DEFAULT']].each do |sev|
      d.emit({'message' => log_entry(emit_index), 'severity' => sev[0]})
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

  def test_multiple_logs
    setup_gce_metadata_stubs
    setup_logging_stubs
    d = create_driver()
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
    setup_gce_metadata_stubs
    # The API Client should not retry this and the plugin should consume
    # the exception.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 400, :body => "Bad Request")
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    d.run
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), :times => 1)
  end

  # helper for the ClientError retriable special cases below.
  def client_error_helper(message)
    setup_gce_metadata_stubs
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 401, :body => message)
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    exception_count = 0
    begin
      d.run
    rescue Google::APIClient::ClientError => error
      assert_equal message, error.message
      exception_count += 1
    end
    assert_requested(:post, uri_for_log(COMPUTE_PARAMS), :times => 2)
    assert_equal 1, exception_count
  end

  def test_client_error_invalid_credentials
    client_error_helper("Invalid Credentials")
  end

  def test_client_error_caller_does_not_have_permission
    client_error_helper("The caller does not have permission")
  end

  def test_client_error_request_had_invalid_credentials
    client_error_helper("Request had invalid credentials.")
  end

  def test_client_error_project_has_not_enabled_the_api
    client_error_helper("Project has not enabled the API. Please use Google Developers Console to activate the API for your project.")
  end

  def test_client_error_unable_to_fetch_accesss_token
    client_error_helper("Unable to fetch access token (no scopes configured?)")
  end

  def test_server_error
    setup_gce_metadata_stubs
    # The API client should retry this once, then throw an exception which
    # gets propagated through the plugin.
    stub_request(:post, uri_for_log(COMPUTE_PARAMS)).to_return(
        :status => 500, :body => "Server Error")
    d = create_driver()
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
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver()
    d.emit({'message' => log_entry(0)})
    d.run
    verify_log_entries(1, VMENGINE_PARAMS)
  end

  def test_multiple_managed_vm_logs
    setup_gce_metadata_stubs
    setup_managed_vm_metadata_stubs
    setup_logging_stubs
    d = create_driver()
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

  # Make parse_severity public so we can test it.
  class Fluent::GoogleCloudOutput
    public :parse_severity
  end

  def test_parse_severity
    test_obj = Fluent::GoogleCloudOutput.new

    # known severities should translate to themselves, regardless of case
    ['DEFAULT', 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL',
     'ALERT', 'EMERGENCY'].each do |severity|
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

  def uri_for_log(config)
    'https://logging.googleapis.com/v1beta3/projects/' + config['project_id'] +
        '/logs/' + config['log_name'] + '/entries:write'
  end

  def stub_metadata_request(metadata_path, response_body)
    stub_request(:get, 'http://metadata/computeMetadata/v1/' + metadata_path).
      to_return(:body => response_body, :status => 200,
                :headers => {'Content-Length' => response_body.length})
  end

  def setup_gce_metadata_stubs
    # Create stubs for all the GCE metadata lookups the agent needs to make.
    stub_metadata_request('project/project-id', PROJECT_ID)
    stub_metadata_request('instance/zone', FULLY_QUALIFIED_ZONE)
    stub_metadata_request('instance/id', VM_ID)
    stub_metadata_request('instance/attributes/',
                          "attribute1\nattribute2\nattribute3")

    # Used by 'googleauth' to test whether we're running on GCE.
    # It only cares about the request succeeding with Metdata-Flavor: Google.
    stub_request(:get, 'http://169.254.169.254').
      to_return(:status => 200, :headers => {'Metadata-Flavor' => 'Google'})

    # Used by 'googleauth' to fetch the default service account credentials.
    stub_request(:get, 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token').
      to_return(:body => "{\"access_token\": \"#{FAKE_AUTH_TOKEN}\"}",
                :status => 200,
                :headers => {'Content-Length' => FAKE_AUTH_TOKEN.length,
                             'Content-Type' => 'application/json' })
  end

  def setup_logging_stubs
    [COMPUTE_PARAMS, VMENGINE_PARAMS, CUSTOM_PARAMS].each do |params|
      stub_request(:post, uri_for_log(params)).to_return do |request|
        @logs_sent << JSON.parse(request.body)
        {:body => ''}
      end
    end
  end

  def setup_auth_stubs
    # Used when loading credentials from a JSON file.
    stub_request(:post, 'https://www.googleapis.com/oauth2/v3/token').
      with(:body => hash_including({:grant_type => AUTH_GRANT_TYPE})).
      to_return(:body => "{\"access_token\": \"#{FAKE_AUTH_TOKEN}\"}",
                :status => 200,
                :headers => {'Content-Length' => FAKE_AUTH_TOKEN.length,
                             'Content-Type' => 'application/json' })
    # Used for 'private_key' auth.
    stub_request(:post, 'https://accounts.google.com/o/oauth2/token').
      with(:body => hash_including({:grant_type => AUTH_GRANT_TYPE})).
      to_return(:body => "{\"access_token\": \"#{FAKE_AUTH_TOKEN}\"}",
                :status => 200,
                :headers => {'Content-Length' => FAKE_AUTH_TOKEN.length,
                             'Content-Type' => 'application/json' })
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
    all_labels ||= common_labels
    all_labels.merge!(entry['metadata']['labels'] || {})
    all_labels.each do |key, value|
      assert expected_labels.has_key?(key), "Unexpected label #{key} => #{value}"
      assert_equal value, expected_labels[key],
          "Value mismatch - expected #{expected_labels[key]} in #{key} => #{value}"
    end
    assert_equal expected_labels.length, all_labels.length,
        ("Expected #{expected_labels.length} labels, got " +
         "#{all_labels.length}")
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type='textPayload')
    i = 0
    @logs_sent.each do |batch|
      batch['entries'].each do |entry|
        assert entry.has_key?(payload_type)
        if (payload_type == 'textPayload')
          # Check the payload for textPayload, otherwise it is up to the caller.
          assert_equal "test log entry #{i}", entry['textPayload'], batch
        end

        assert_equal params['zone'], entry['metadata']['zone']
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
