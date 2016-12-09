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

require_relative 'base_test'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputTest < Test::Unit::TestCase
  include BaseTest

  def test_configure_use_grpc
    setup_gce_metadata_stubs
    d = create_driver
    assert_false d.instance.instance_variable_get(:@use_grpc)
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

  HTTP_REQUEST_MESSAGE_WITHOUT_REFERER = {
    'requestMethod' => 'POST',
    'requestUrl' => 'http://example/',
    'requestSize' => 210,
    'status' => 200,
    'responseSize' => 65,
    'userAgent' => 'USER AGENT 1.0',
    'remoteIp' => '55.55.55.55',
    'referer' => nil,
    'cacheHit' => false,
    'validatedWithOriginServer' => true
  }

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

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput, tag).configure(conf, use_v1_config: true)
  end

  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload', &block)
    verify_json_log_entries(n, params, payload_type, &block)
  end

  # For an optional field with default values, Protobuf omits the field when
  # deserialize it to json. So we need to add an extra check for gRPC which uses
  # Protobuf.
  def assert_with_default_check(field, expected_value, _default_value, entry)
    if expected_value == 'DEBUG'
      # For some reason we return '100' instead of 'DEBUG' for the non-grpc
      # path. And the original test asserts this.
      # TODO(lingshi) figure out if this is a bug or expected behavior.
      assert_equal 100, field, entry
    else
      assert_equal expected_value, field, entry
    end
  end

  def http_request_message
    HTTP_REQUEST_MESSAGE
  end

  def http_request_message_without_referer
    HTTP_REQUEST_MESSAGE_WITHOUT_REFERER
  end

  def get_fields(struct_payload)
    struct_payload
  end

  def get_struct(field)
    field
  end

  def get_string(field)
    field
  end

  def get_number(field)
    field
  end
end
