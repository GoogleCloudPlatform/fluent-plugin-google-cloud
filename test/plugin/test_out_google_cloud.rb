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

  def test_partial_success
    setup_gce_metadata_stubs
    setup_prometheus
    # The API Client should not retry this and the plugin should consume
    # the exception.
    root_error_code = PARTIAL_SUCCESS_RESPONSE_BODY['error']['code']
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: root_error_code,
                 body: PARTIAL_SUCCESS_RESPONSE_BODY.to_json)
    d = create_driver(PROMETHEUS_ENABLE_CONFIG + PARTIAL_SUCCESS_CONFIG)
    4.times do |i|
      d.emit('message' => log_entry(i.to_s))
    end
    d.run
    assert_prometheus_metric_value(
      :stackdriver_successful_requests_count, 0, grpc: false, code: 200)
    assert_prometheus_metric_value(
      :stackdriver_failed_requests_count, 1, grpc: false, code: root_error_code)
    assert_prometheus_metric_value(
      :stackdriver_ingested_entries_count, 1, grpc: false, code: 200)
    assert_prometheus_metric_value(
      :stackdriver_dropped_entries_count, 2, grpc: false, code: 3)
    assert_prometheus_metric_value(
      :stackdriver_dropped_entries_count, 1, grpc: false, code: 7)
    assert_prometheus_metric_value(
      :stackdriver_retried_entries_count, 0, grpc: false)
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 1)
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

  # TODO: The code in the non-gRPC and gRPC tests is nearly identical.
  # Refactor and remove duplication.
  # TODO: Use status codes instead of int literals.
  def test_prometheus_metrics
    setup_gce_metadata_stubs
    [
      # Single successful request.
      [200, 1, 1, [1, 0, 1, 0, 0]],
      # Several successful requests.
      [200, 2, 1, [2, 0, 2, 0, 0]],
      # Single successful request with several entries.
      [200, 1, 2, [1, 0, 2, 0, 0]],
      # Single failed request that causes logs to be dropped.
      [401, 1, 1, [0, 1, 0, 1, 0]],
      # Single failed request that escalates without logs being dropped with
      # several entries.
      [500, 1, 2, [0, 1, 0, 0, 2]]
    ].each do |code, request_count, entry_count, metric_values|
      setup_prometheus
      # TODO: Do this as part of setup_logging_stubs.
      stub_request(:post, WRITE_LOG_ENTRIES_URI)
        .to_return(status: code, body: 'Some Message')
      (1..request_count).each do
        d = create_driver(PROMETHEUS_ENABLE_CONFIG)
        (1..entry_count).each do |i|
          d.emit('message' => log_entry(i.to_s))
        end
        # rubocop:disable Lint/HandleExceptions
        begin
          d.run
        rescue Google::Apis::AuthorizationError
        rescue Google::Apis::ServerError
        end
        # rubocop:enable Lint/HandleExceptions
      end
      successful_requests_count, failed_requests_count,
        ingested_entries_count, dropped_entries_count,
        retried_entries_count = metric_values
      assert_prometheus_metric_value(:stackdriver_successful_requests_count,
                                     successful_requests_count,
                                     grpc: false, code: 200)
      assert_prometheus_metric_value(:stackdriver_failed_requests_count,
                                     failed_requests_count,
                                     grpc: false, code: code)
      assert_prometheus_metric_value(:stackdriver_ingested_entries_count,
                                     ingested_entries_count,
                                     grpc: false, code: 200)
      assert_prometheus_metric_value(:stackdriver_dropped_entries_count,
                                     dropped_entries_count,
                                     grpc: false, code: code)
      assert_prometheus_metric_value(:stackdriver_retried_entries_count,
                                     retried_entries_count,
                                     grpc: false, code: code)
    end
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

    assert_equal(100, test_obj.parse_severity(100))

    assert_equal('DEFAULT', test_obj.parse_severity('-100'))
    assert_equal('DEFAULT', test_obj.parse_severity('105 100'))

    # synonyms for existing log levels
    assert_equal('ERROR', test_obj.parse_severity('ERR'))
    assert_equal('ERROR', test_obj.parse_severity('SEVERE'))
    assert_equal('WARNING', test_obj.parse_severity('WARN'))
    assert_equal('CRITICAL', test_obj.parse_severity('FATAL'))
    assert_equal('DEBUG', test_obj.parse_severity('TRACE'))
    assert_equal('DEBUG', test_obj.parse_severity('TRACE_INT'))
    assert_equal('DEBUG', test_obj.parse_severity('FINE'))
    assert_equal('DEBUG', test_obj.parse_severity('FINER'))
    assert_equal('DEBUG', test_obj.parse_severity('FINEST'))
    assert_equal('DEBUG', test_obj.parse_severity('CONFIG'))

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
    assert_equal('DEFAULT', test_obj.parse_severity(nil))
    assert_equal('DEFAULT', test_obj.parse_severity(Object.new))
    assert_equal('DEFAULT', test_obj.parse_severity({}))
    assert_equal('DEFAULT', test_obj.parse_severity([]))
    assert_equal('DEFAULT', test_obj.parse_severity(100.0))
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

  WRITE_LOG_ENTRIES_URI =
    'https://logging.googleapis.com/v2/entries:write'.freeze

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

  # 'responseSize' and 'requestSize' are Integers in the gRPC proto, yet Strings
  # in REST API client.
  # TODO(qingling128): Address this accordingly once the following question is
  # answered: https://github.com/google/google-api-ruby-client/issues/619.
  # If this discrepancy is legit, add some comments to explain the reason.
  # Otherwise once the discrepancy is fixed, we need to upgrade to that version
  # and change our tests accordingly.
  def http_request_message
    HTTP_REQUEST_MESSAGE.merge(
      'responseSize' => HTTP_REQUEST_MESSAGE['responseSize'].to_s,
      'requestSize' => HTTP_REQUEST_MESSAGE['requestSize'].to_s
    )
  end

  # 'line' is an Integer in the gRPC proto, yet a String in the REST API client.
  def source_location_message
    SOURCE_LOCATION_MESSAGE.merge(
      'line' => SOURCE_LOCATION_MESSAGE['line'].to_s
    )
  end
end
