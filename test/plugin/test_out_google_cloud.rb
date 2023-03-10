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

require 'fluent/test/startup_shutdown'
require 'net/http'

require_relative 'base_test'
require_relative 'test_driver'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputTest < Test::Unit::TestCase
  include BaseTest
  extend Fluent::Test::StartupShutdown

  def test_configure_use_grpc
    setup_gce_metadata_stubs
    d = create_driver
    assert_false d.instance.instance_variable_get(:@use_grpc)
  end

  def test_user_agent
    setup_gce_metadata_stubs
    user_agent = nil
    stub_request(:post, WRITE_LOG_ENTRIES_URI).to_return do |request|
      user_agent = request.headers['User-Agent']
      { body: '' }
    end
    d = create_driver
    d.emit('message' => log_entry(0))
    d.run
    assert_match Regexp.new("#{Fluent::GoogleCloudOutput::PLUGIN_NAME}/" \
                            "#{Fluent::GoogleCloudOutput::PLUGIN_VERSION}"), \
                 user_agent
  end

  def test_client_status400
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
  def test_client_status401
    setup_gce_metadata_stubs
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: 401, body: 'Unauthorized')
    d = create_driver
    d.emit('message' => log_entry(0))
    begin
      d.run
    rescue Google::Apis::AuthorizationError => e
      assert_equal 'Unauthorized', e.message
    end
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 2)
  end

  def test_partial_success
    setup_gce_metadata_stubs
    clear_metrics
    # The API Client should not retry this and the plugin should consume
    # the exception.
    root_error_code = PARTIAL_SUCCESS_RESPONSE_BODY['error']['code']
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: root_error_code,
                 body: PARTIAL_SUCCESS_RESPONSE_BODY.to_json)
    d = create_driver(ENABLE_PROMETHEUS_CONFIG)
    4.times do |i|
      d.emit('message' => log_entry(i.to_s))
    end
    d.run
    assert_prometheus_metric_value(
      :stackdriver_successful_requests_count, 1,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 200
    )
    assert_prometheus_metric_value(
      :stackdriver_ingested_entries_count, 1,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 200
    )
    assert_prometheus_metric_value(
      :stackdriver_dropped_entries_count, 2,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 3
    )
    assert_prometheus_metric_value(
      :stackdriver_dropped_entries_count, 1,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 7
    )
    assert_requested(:post, WRITE_LOG_ENTRIES_URI, times: 1)
  end

  def test_non_api_error
    setup_gce_metadata_stubs
    clear_metrics
    # The API Client should not retry this and the plugin should consume
    # the exception.
    root_error_code = PARSE_ERROR_RESPONSE_BODY['error']['code']
    stub_request(:post, WRITE_LOG_ENTRIES_URI)
      .to_return(status: root_error_code,
                 body: PARSE_ERROR_RESPONSE_BODY.to_json)
    d = create_driver(ENABLE_PROMETHEUS_CONFIG)
    d.emit('message' => log_entry(0))
    d.run
    assert_prometheus_metric_value(
      :stackdriver_successful_requests_count, 0,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 200
    )
    assert_prometheus_metric_value(
      :stackdriver_failed_requests_count, 1,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 400
    )
    assert_prometheus_metric_value(
      :stackdriver_ingested_entries_count, 0,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 200
    )
    assert_prometheus_metric_value(
      :stackdriver_dropped_entries_count, 1,
      'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
      grpc: false, code: 400
    )
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
    rescue Google::Apis::ServerError => e
      assert_equal 'Server error', e.message
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
      [%w[INFO INFO], %w[warn WARNING], %w[E ERROR], %w[BLAH DEFAULT],
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
    %w[DEFAULT DEBUG INFO NOTICE WARNING ERROR CRITICAL ALERT EMERGENCY].each \
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

  def test_statusz_endpoint
    setup_gce_metadata_stubs
    WebMock.disable_net_connect!(allow_localhost: true)
    # TODO(davidbtucker): Consider searching for an unused port
    # instead of hardcoding a constant here.
    d = create_driver(CONFIG_STATUSZ)
    d.run do
      resp = Net::HTTP.get('127.0.0.1', '/statusz', 5678)
      must_match = [
        '<h1>Status for .*</h1>.*',

        '\badjust_invalid_timestamps\b.*\bfalse\b',
        '\bautoformat_stackdriver_trace\b.*\bfalse\b',
        '\bcoerce_to_utf8\b.*\bfalse\b',
        '\bdetect_json\b.*\btrue\b',
        '\bdetect_subservice\b.*\bfalse\b',
        '\benable_monitoring\b.*\btrue\b',
        '\bhttp_request_key\b.*\btest_http_request_key\b',
        '\binsert_id_key\b.*\btest_insert_id_key\b',
        '\bk8s_cluster_location\b.*\btest-k8s-cluster-location\b',
        '\bk8s_cluster_name\b.*\btest-k8s-cluster-name\b',
        '\bkubernetes_tag_regexp\b.*\b.*test-regexp.*\b',
        '\blabel_map\b.*{"label_map_key"=>"label_map_value"}',
        '\blabels_key\b.*\btest_labels_key\b',
        '\blabels\b.*{"labels_key"=>"labels_value"}',
        '\blogging_api_url\b.*\bhttp://localhost:52000\b',
        '\bmonitoring_type\b.*\bnot_prometheus\b',
        '\bnon_utf8_replacement_string\b.*\bzzz\b',
        '\boperation_key\b.*\btest_operation_key\b',
        '\bproject_id\b.*\btest-project-id-123\b',
        '\brequire_valid_tags\b.*\btrue\b',
        '\bsource_location_key\b.*\btest_source_location_key\b',
        '\bspan_id_key\b.*\btest_span_id_key\b',
        '\bsplit_logs_by_tag\b.*\btrue\b',
        '\bstatusz_port\b.*\b5678\b',
        '\bsubservice_name\b.*\btest_subservice_name\b',
        '\btrace_key\b.*\btest_trace_key\b',
        '\btrace_sampled_key\b.*\btest_trace_sampled_key\b',
        '\buse_aws_availability_zone\b.*\bfalse\b',
        '\buse_grpc\b.*\btrue\b',
        '\buse_metadata_service\b.*\bfalse\b',
        '\bvm_id\b.*\b12345\b',
        '\bvm_name\b.*\btest.hostname.org\b',
        '\bzone\b.*\basia-east2\b',

        '^</html>$'
      ]
      must_match.each do |re|
        assert_match Regexp.new(re), resp
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
  def setup_logging_stubs(_error = nil, code = nil, message = 'some message')
    stub_request(:post, WRITE_LOG_ENTRIES_URI).to_return do |request|
      @logs_sent << JSON.parse(request.body)
      { status: code, body: message }
    end
    yield
  end

  # Whether this is the grpc path
  def use_grpc
    false
  end

  # The OK status code for the grpc path.
  def ok_status_code
    200
  end

  # A client side error status code for the grpc path.
  def client_error_status_code
    401
  end

  # A server side error status code for the grpc path.
  def server_error_status_code
    500
  end

  # The parent error type to expect in the mock
  def mock_error_type
    Google::Apis::Error
  end

  # The conversions from user input to output.
  def latency_conversion
    {
      '32 s' => { 'seconds' => 32 },
      '32s' => { 'seconds' => 32 },
      '0.32s' => { 'nanos' => 320_000_000 },
      ' 123 s ' => { 'seconds' => 123 },
      '1.3442 s' => { 'seconds' => 1, 'nanos' => 344_200_000 },

      # Test whitespace.
      # \t: tab. \r: carriage return. \n: line break.
      # \v: vertical whitespace. \f: form feed.
      "\t123.5\ts\t" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\r123.5\rs\r" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\n123.5\ns\n" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\v123.5\vs\v" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\f123.5\fs\f" => { 'seconds' => 123, 'nanos' => 500_000_000 },
      "\r123.5\ts\f" => { 'seconds' => 123, 'nanos' => 500_000_000 }
    }
  end

  # Create a Fluentd output test driver with the Google Cloud Output plugin.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG,
                    tag = 'test',
                    multi_tags = false)
    driver = if multi_tags
               Fluent::Test::MultiTagBufferedOutputTestDriver.new(
                 Fluent::GoogleCloudOutput
               )
             else
               Fluent::Test::BufferedOutputTestDriver.new(
                 Fluent::GoogleCloudOutput, tag
               )
             end
    driver.configure(conf, true)
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(expected_count, params, payload_type = 'textPayload',
                         check_exact_entry_labels = true, &block)
    verify_json_log_entries(expected_count, params, payload_type,
                            check_exact_entry_labels, &block)
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

  def expected_operation_message2
    OPERATION_MESSAGE2
  end

  # Directly return the timestamp value, which should be a hash two keys:
  # "seconds" and "nanos".
  def timestamp_parse(timestamp)
    timestamp
  end
end
