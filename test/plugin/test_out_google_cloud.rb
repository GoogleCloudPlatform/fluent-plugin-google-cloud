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
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: 400, body: 'Bad Request')
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 1)
  end

  # All credentials errors resolve to a 401.
  def test_client_401
    setup_gce_metadata_stubs
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: 401, body: 'Unauthorized')
    d = create_driver
    d.emit('message' => log_entry(0))
    begin
      d.run
    rescue Google::Apis::AuthorizationError => error
      assert_equal 'Unauthorized', error.message
    end
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 2)
  end

  def test_server_error
    setup_gce_metadata_stubs
    # The API client should retry this once, then throw an exception which
    # gets propagated through the plugin.
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
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
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 1)
    assert_equal 1, exception_count
  end

  # This test looks similar between the grpc and non-grpc paths except that when
  # parsing "105", the grpc path responds with "DEBUG", while the non-grpc path
  # responds with "100".
  #
  # TODO(lingshi) consolidate the tests between the grpc path and the non-grpc
  # path, or at least split into two tests, one with string severities and one
  # with numeric severities.
  def test_severities
    setup_gce_metadata_stubs
    expected_severity = []
    emit_index = 0
    setup_logging_stubs do
      d = create_driver
      # Array of pairs of [parsed_severity, expected_severity]
      [%w(INFO INFO), %w(warn WARNING), %w(E ERROR), %w(BLAH DEFAULT),
       ['105', 100], ['', 'DEFAULT']].each do |sev|
        d.emit('message' => log_entry(emit_index), 'severity' => sev[0])
        expected_severity.push(sev[1])
        emit_index += 1
      end
      d.run
    end
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal expected_severity[verify_index],
                   entry['severity'], entry
      verify_index += 1
    end
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

  def test_non_integer_timestamp
    setup_gce_metadata_stubs
    time = Time.now
    [
      { 'seconds' => nil, 'nanos' => nil },
      { 'seconds' => nil, 'nanos' => time.tv_nsec },
      { 'seconds' => 'seconds', 'nanos' => time.tv_nsec },
      { 'seconds' => time.tv_sec, 'nanos' => 'nanos' },
      { 'seconds' => time.tv_sec, 'nanos' => nil }
    ].each do |timestamp|
      setup_logging_stubs do
        d = create_driver
        @logs_sent = []
        d.emit('message' => log_entry(0), 'timestamp' => timestamp)
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS) do |entry|
        assert_equal timestamp, entry['timestamp'], 'Test with timestamp ' \
                     "'#{timestamp}' failed for entry: '#{entry}'."
      end
    end
  end

  private

  WRITE_LOG_ENTRIES_URI = 'https://logging.googleapis.com/v2beta1/entries:write'

  def rename_key(hash, old_key, new_key)
    hash.merge(new_key => hash[old_key]).reject { |k, _| k == old_key }
  end

  # Set up http stubs to mock the external calls.
  def setup_logging_stubs
    stub_request(:post, WRITE_LOG_ENTRIES_URI).to_return do |request|
      @logs_sent << JSON.parse(request.body)
      { body: '' }
    end
    yield
  end

  # Create a Fluentd output test driver with the Google Cloud Output plugin.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    Fluent::Test::BufferedOutputTestDriver.new(
      Fluent::GoogleCloudOutput, tag).configure(conf, true)
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload', &block)
    verify_json_log_entries(n, params, payload_type, &block)
  end

  # For an optional field with default values, Protobuf omits the field when it
  # is deserialized to json. So we need to add an extra check for gRPC which
  # uses Protobuf.
  #
  # An optional block can be passed in if we need to assert something other than
  # a plain equal. e.g. assert_in_delta.
  def assert_equal_with_default(field, expected_value, _default_value, entry)
    if block_given?
      yield
    else
      assert_equal expected_value, field, entry
    end
  end

  # Get the fields of the payload.
  def get_fields(payload)
    payload
  end

  # Get the value of a struct field.
  def get_struct(field)
    field
  end

  # Get the value of a string field.
  def get_string(field)
    field
  end

  # Get the value of a number field.
  def get_number(field)
    field
  end

  # The null value.
  def null_value
    nil
  end
end
