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

require 'grpc'

require_relative 'base_test'
require_relative 'test_driver'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputGRPCTest < Test::Unit::TestCase
  include BaseTest

  def test_configure_use_grpc
    setup_gce_metadata_stubs
    d = create_driver
    assert_true d.instance.instance_variable_get(:@use_grpc)
  end

  def test_user_agent
    setup_gce_metadata_stubs

    user_agent = nil
    # Record user agent when creating a GRPC::Core::Channel.
    GRPC::Core::Channel.class_eval do
      old_initialize = instance_method(:initialize)
      define_method(:initialize) do |url, args, creds|
        user_agent = args['grpc.primary_user_agent']
        old_initialize.bind(self).call(url, args, creds)
      end
    end

    d = create_driver
    d.instance.send :init_api_client
    assert_match Regexp.new("#{Fluent::GoogleCloudOutput::PLUGIN_NAME}/" \
                            "#{Fluent::GoogleCloudOutput::PLUGIN_VERSION}"), \
                 user_agent
  end

  def test_client_error
    setup_gce_metadata_stubs
    {
      GRPC::Core::StatusCodes::CANCELLED => 'Cancelled',
      GRPC::Core::StatusCodes::UNKNOWN => 'Unknown',
      GRPC::Core::StatusCodes::INVALID_ARGUMENT => 'InvalidArgument',
      GRPC::Core::StatusCodes::NOT_FOUND => 'NotFound',
      GRPC::Core::StatusCodes::PERMISSION_DENIED => 'PermissionDenied',
      GRPC::Core::StatusCodes::RESOURCE_EXHAUSTED => 'ResourceExhausted',
      GRPC::Core::StatusCodes::FAILED_PRECONDITION => 'FailedPrecondition',
      GRPC::Core::StatusCodes::ABORTED => 'Aborted',
      GRPC::Core::StatusCodes::UNAUTHENTICATED => 'Unauthenticated'
    }.each_with_index do |(code, message), index|
      setup_logging_stubs(nil, code, message) do
        d = create_driver(USE_GRPC_CONFIG, 'test')
        # The API Client should not retry this and the plugin should consume the
        # exception.
        d.emit('message' => log_entry(0))
        d.run
      end
      assert_equal 1, @failed_attempts.size, "Index #{index} failed."
    end
  end

  def test_invalid_error
    setup_gce_metadata_stubs
    setup_logging_stubs(RuntimeError.new('Some non-gRPC error')) do
      d = create_driver(USE_GRPC_CONFIG, 'test')
      # The API Client should not retry this and the plugin should consume the
      # exception.
      d.emit('message' => log_entry(0))
      d.run
    end
    assert_equal 1, @failed_attempts.size
  end

  def test_partial_success
    setup_gce_metadata_stubs
    clear_metrics
    setup_logging_stubs(
      GRPC::PermissionDenied.new('User not authorized.',
                                 PARTIAL_SUCCESS_GRPC_METADATA)) do
      # The API Client should not retry this and the plugin should consume
      # the exception.
      d = create_driver(ENABLE_PROMETHEUS_CONFIG)
      4.times do |i|
        d.emit('message' => log_entry(i.to_s))
      end
      d.run
      assert_prometheus_metric_value(
        :stackdriver_successful_requests_count, 1,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::OK)
      assert_prometheus_metric_value(
        :stackdriver_failed_requests_count, 0,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::PERMISSION_DENIED)
      assert_prometheus_metric_value(
        :stackdriver_ingested_entries_count, 1,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::OK)
      assert_prometheus_metric_value(
        :stackdriver_dropped_entries_count, 2,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::INVALID_ARGUMENT)
      assert_prometheus_metric_value(
        :stackdriver_dropped_entries_count, 1,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::PERMISSION_DENIED)
    end
  end

  def test_non_api_error
    setup_gce_metadata_stubs
    clear_metrics
    setup_logging_stubs(
      GRPC::InvalidArgument.new('internal client error',
                                PARSE_ERROR_GRPC_METADATA)) do
      # The API Client should not retry this and the plugin should consume
      # the exception.
      d = create_driver(ENABLE_PROMETHEUS_CONFIG)
      d.emit('message' => log_entry(0))
      d.run
      assert_prometheus_metric_value(
        :stackdriver_successful_requests_count, 0,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::OK)
      assert_prometheus_metric_value(
        :stackdriver_failed_requests_count, 1,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::INVALID_ARGUMENT)
      assert_prometheus_metric_value(
        :stackdriver_ingested_entries_count, 0,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::OK)
      assert_prometheus_metric_value(
        :stackdriver_dropped_entries_count, 1,
        'agent.googleapis.com/agent', OpenCensus::Stats::Aggregation::Sum, d,
        grpc: use_grpc, code: GRPC::Core::StatusCodes::INVALID_ARGUMENT)
    end
  end

  def test_server_error
    setup_gce_metadata_stubs
    {
      GRPC::Core::StatusCodes::DEADLINE_EXCEEDED => 'DeadlineExceeded',
      GRPC::Core::StatusCodes::UNIMPLEMENTED => 'Unimplemented',
      GRPC::Core::StatusCodes::INTERNAL => 'Internal',
      GRPC::Core::StatusCodes::UNAVAILABLE => 'Unavailable'
    }.each_with_index do |(code, message), index|
      exception_count = 0
      setup_logging_stubs(nil, code, message) do
        d = create_driver(USE_GRPC_CONFIG, 'test')
        # The API client should retry this once, then throw an exception which
        # gets propagated through the plugin
        d.emit('message' => log_entry(0))
        begin
          d.run
        rescue GRPC::BadStatus => error
          assert_equal "#{code}:#{message}", error.message
          exception_count += 1
        end
      end
      assert_equal 1, @failed_attempts.size, "Index #{index} failed."
      assert_equal 1, exception_count, "Index #{index} failed."
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
       %w(105 DEBUG), ['', 'DEFAULT']].each do |sev|
        d.emit('message' => log_entry(emit_index), 'severity' => sev[0])
        expected_severity.push(sev[1])
        emit_index += 1
      end
      d.run
    end
    verify_index = 0
    verify_log_entries(emit_index, COMPUTE_PARAMS) do |entry|
      assert_equal_with_default(entry['severity'],
                                expected_severity[verify_index],
                                'DEFAULT', entry)
      verify_index += 1
    end
  end

  # TODO(qingling128): Verify if we need this on the REST side and add it if
  # needed.
  def test_struct_payload_non_utf8_log
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('msg' => log_entry(0),
             'normal_key' => "test#{non_utf8_character}non utf8",
             "non_utf8#{non_utf8_character}key" => 5000,
             'nested_struct' => { "non_utf8#{non_utf8_character}key" => \
                                  "test#{non_utf8_character}non utf8" },
             'null_field' => nil)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'jsonPayload') do |entry|
      fields = entry['jsonPayload']
      assert_equal 5, fields.size, entry
      assert_equal 'test log entry 0', fields['msg'], entry
      assert_equal 'test non utf8', fields['normal_key'], entry
      assert_equal 5000, fields['non_utf8 key'], entry
      assert_equal 'test non utf8', fields['nested_struct']['non_utf8 key'],
                   entry
      assert_nil fields['null_field'], entry
    end
  end

  def test_non_integer_timestamp
    setup_gce_metadata_stubs
    time = Time.now
    {
      { 'seconds' => nil, 'nanos' => nil } => nil,
      { 'seconds' => nil, 'nanos' => time.tv_nsec } => nil,
      { 'seconds' => 'seconds', 'nanos' => time.tv_nsec } => nil,
      { 'seconds' => time.tv_sec, 'nanos' => 'nanos' } => \
        time.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
      { 'seconds' => time.tv_sec, 'nanos' => nil } => \
        time.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    }.each do |input, expected|
      setup_logging_stubs do
        d = create_driver
        @logs_sent = []
        d.emit('message' => log_entry(0), 'timestamp' => input)
        d.run
      end
      verify_log_entries(1, COMPUTE_PARAMS) do |entry|
        assert_equal expected, entry['timestamp'], 'Test with timestamp ' \
                     "'#{input}' failed for entry: '#{entry}'."
      end
    end
  end

  private

  WriteLogEntriesRequest = Google::Logging::V2::WriteLogEntriesRequest
  WriteLogEntriesResponse = Google::Logging::V2::WriteLogEntriesResponse

  USE_GRPC_CONFIG = %(
    use_grpc true
  ).freeze

  # The conversions from user input to output.
  def latency_conversion
    {
      '32 s' => '32s',
      '32s' => '32s',
      '0.32s' => '0.320s',
      ' 123 s ' => '123s',
      '1.3442 s' => '1.34420s',

      # Test whitespace.
      # \t: tab. \r: carriage return. \n: line break.
      # \v: vertical whitespace. \f: form feed.
      "\t123.5\ts\t" => '123.50s',
      "\r123.5\rs\r" => '123.50s',
      "\n123.5\ns\n" => '123.50s',
      "\v123.5\vs\v" => '123.50s',
      "\f123.5\fs\f" => '123.50s',
      "\r123.5\ts\f" => '123.50s'
    }
  end

  # Create a Fluentd output test driver with the Google Cloud Output plugin with
  # grpc enabled. The signature of this method is different between the grpc
  # path and the non-grpc path. For grpc, an additional grpc stub class can be
  # passed in to construct the mock used by the test driver.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG,
                    tag = 'test',
                    multi_tags = false)
    conf += USE_GRPC_CONFIG
    driver = if multi_tags
               Fluent::Test::MultiTagBufferedOutputTestDriver.new(
                 GoogleCloudOutputWithGRPCMock.new(@grpc_stub))
             else
               Fluent::Test::BufferedOutputTestDriver.new(
                 GoogleCloudOutputWithGRPCMock.new(@grpc_stub), tag)
             end
    driver.configure(conf, true)
  end

  # Google Cloud Fluent output stub with grpc mock.
  class GoogleCloudOutputWithGRPCMock < Fluent::GoogleCloudOutput
    def initialize(grpc_stub)
      super()
      @grpc_stub = grpc_stub
    end

    def api_client
      @grpc_stub
    end
  end

  # GRPC logging mock that successfully logs the records.
  class GRPCLoggingMockService <
      Google::Cloud::Logging::V2::LoggingServiceV2Client
    def initialize(requests_received)
      super()
      @requests_received = requests_received
    end

    def write_log_entries(entries,
                          log_name: nil,
                          resource: nil,
                          labels: nil,
                          partial_success: nil)
      request = Google::Apis::LoggingV2::WriteLogEntriesRequest.new(
        log_name: log_name,
        resource: resource,
        labels: labels,
        entries: entries,
        partial_success: partial_success
      )
      @requests_received << request
      WriteLogEntriesResponse.new
    end
  end

  # GRPC logging mock that fails and returns server side or client side errors.
  class GRPCLoggingMockFailingService <
      Google::Cloud::Logging::V2::LoggingServiceV2Client
    def initialize(error, failed_attempts)
      super()
      @error = error
      @failed_attempts = failed_attempts
    end

    # rubocop:disable Lint/UnusedMethodArgument
    def write_log_entries(entries,
                          log_name: nil,
                          resource: nil,
                          labels: nil,
                          partial_success: nil)
      @failed_attempts << 1
      begin
        raise @error
      rescue
        # Google::Gax::GaxError will wrap the latest thrown exception as @cause.
        raise Google::Gax::GaxError, 'This test message does not matter.'
      end
    end
    # rubocop:enable Lint/UnusedMethodArgument
  end

  # Set up grpc stubs to mock the external calls.
  def setup_logging_stubs(error = nil, code = nil, message = 'some message')
    if error.nil? && (code.nil? || code == 0)
      @requests_sent = []
      @grpc_stub = GRPCLoggingMockService.new(@requests_sent)
    else
      @failed_attempts = []
      # Only fall back to constructing an error with code and message if no
      # error is passed in.
      error ||= GRPC::BadStatus.new_status_exception(code, message)
      @grpc_stub = GRPCLoggingMockFailingService.new(error, @failed_attempts)
    end
    yield
  end

  # Whether this is the grpc path
  def use_grpc
    true
  end

  # The OK status code for the grpc path.
  def ok_status_code
    0
  end

  # A client side error status code for the grpc path.
  def client_error_status_code
    16
  end

  # A server side error status code for the grpc path.
  def server_error_status_code
    13
  end

  # The parent error type to expect in the mock
  def mock_error_type
    GRPC::BadStatus
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload',
                         check_exact_entry_labels = true, &block)
    @requests_sent.each do |request|
      @logs_sent << {
        'entries' => request.entries.map { |entry| JSON.parse(entry.to_json) },
        'labels' => request.labels,
        'resource' => request.resource,
        'logName' => request.log_name
      }
    end
    verify_json_log_entries(n, params, payload_type, check_exact_entry_labels,
                            &block)
  end

  # Use the right single quotation mark as the sample non-utf8 character.
  def non_utf8_character
    [0x92].pack('C*')
  end

  # For an optional field with default values, Protobuf omits the field when it
  # is deserialized to json. So we need to add an extra check for gRPC which
  # uses Protobuf.
  #
  # An optional block can be passed in if we need to assert something other than
  # a plain equal. e.g. assert_in_delta.
  def assert_equal_with_default(field, expected_value, default_value, entry)
    if expected_value == default_value
      assert_nil field
    elsif block_given?
      yield
    else
      assert_equal expected_value, field, entry
    end
  end

  def expected_operation_message2
    # 'last' is a boolean field with false as default value. Protobuf omit
    # fields with default values during deserialization.
    OPERATION_MESSAGE2.reject { |k, _| k == 'last' }
  end

  # Parse timestamp and convert it to a hash with two keys:
  # "seconds" and "nanos".
  def timestamp_parse(timestamp)
    parsed = Time.parse(timestamp)
    {
      'seconds' => parsed.tv_sec,
      'nanos' => parsed.tv_nsec
    }
  end
end
