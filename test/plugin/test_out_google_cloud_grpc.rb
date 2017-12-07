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

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputGRPCTest < Test::Unit::TestCase
  include BaseTest

  def test_configure_use_grpc
    setup_gce_metadata_stubs
    d = create_driver
    assert_true d.instance.instance_variable_get(:@use_grpc)
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
      setup_logging_stubs(true, code, message) do
        d = create_driver(USE_GRPC_CONFIG, 'test')
        # The API Client should not retry this and the plugin should consume the
        # exception.
        d.emit('message' => log_entry(0))
        d.run
      end
      assert_equal 1, @failed_attempts.size, "Index #{index} failed."
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
      setup_logging_stubs(true, code, message) do
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

  # TODO: The code in the non-gRPC and gRPC tests is nearly identical.
  # Refactor and remove duplication.
  # TODO: Use status codes instead of int literals.
  def test_prometheus_metrics
    setup_gce_metadata_stubs
    [
      # Single successful request.
      [false, 0, 1, 1, [1, 0, 1, 0, 0]],
      # Several successful requests.
      [false, 0, 2, 1, [2, 0, 2, 0, 0]],
      # Single successful request with several entries.
      [false, 0, 1, 2, [1, 0, 2, 0, 0]],
      # Single failed request that causes logs to be dropped.
      [true, 16, 1, 1, [0, 1, 0, 1, 0]],
      # Single failed request that escalates without logs being dropped with
      # several entries.
      [true, 13, 1, 2, [0, 0, 0, 0, 2]]
    ].each do |should_fail, code, request_count, entry_count, metric_values|
      setup_prometheus
      (1..request_count).each do
        setup_logging_stubs(should_fail, code, 'SomeMessage') do
          d = create_driver(USE_GRPC_CONFIG + PROMETHEUS_ENABLE_CONFIG, 'test')
          (1..entry_count).each do |i|
            d.emit('message' => log_entry(i.to_s))
          end
          # rubocop:disable Lint/HandleExceptions
          begin
            d.run
          rescue GRPC::BadStatus
          end
          # rubocop:enable Lint/HandleExceptions
        end
      end
      successful_requests_count, failed_requests_count,
        ingested_entries_count, dropped_entries_count,
        retried_entries_count = metric_values
      assert_prometheus_metric_value(:stackdriver_successful_requests_count,
                                     successful_requests_count,
                                     grpc: true, code: 0)
      assert_prometheus_metric_value(:stackdriver_failed_requests_count,
                                     failed_requests_count,
                                     grpc: true, code: code)
      assert_prometheus_metric_value(:stackdriver_ingested_entries_count,
                                     ingested_entries_count,
                                     grpc: true, code: 0)
      assert_prometheus_metric_value(:stackdriver_dropped_entries_count,
                                     dropped_entries_count,
                                     grpc: true, code: code)
      assert_prometheus_metric_value(:stackdriver_retried_entries_count,
                                     retried_entries_count,
                                     grpc: true, code: code)
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
      fields = get_fields(entry['jsonPayload'])
      assert_equal 5, fields.size, entry
      assert_equal 'test log entry 0', get_string(fields['msg']), entry
      assert_equal 'test non utf8', get_string(fields['normal_key']), entry
      assert_equal 5000, get_number(fields['non_utf8 key']), entry
      assert_equal 'test non utf8', get_string(get_fields(get_struct(fields \
                   ['nested_struct']))['non_utf8 key']), entry
      assert_equal null_value, fields['null_field'], entry
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
        { 'seconds' => time.tv_sec },
      { 'seconds' => time.tv_sec, 'nanos' => nil } => \
        { 'seconds' => time.tv_sec }
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

  # Create a Fluentd output test driver with the Google Cloud Output plugin with
  # grpc enabled. The signature of this method is different between the grpc
  # path and the non-grpc path. For grpc, an additional grpc stub class can be
  # passed in to construct the mock used by the test driver.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test')
    conf += USE_GRPC_CONFIG
    Fluent::Test::BufferedOutputTestDriver.new(
      GoogleCloudOutputWithGRPCMock.new(@grpc_stub), tag).configure(conf, true)
  end

  # Google Cloud Fluent output stub with grpc mock.
  class GoogleCloudOutputWithGRPCMock < Fluent::GoogleCloudOutput
    def initialize(grpc_stub)
      super()
      @grpc_stub = grpc_stub
    end

    def api_client
      ssl_creds = GRPC::Core::ChannelCredentials.new
      authentication = Google::Auth.get_application_default
      creds = GRPC::Core::CallCredentials.new(authentication.updater_proc)
      ssl_creds.compose(creds)

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

    def write_log_entries(entries, log_name: nil, resource: nil, labels: nil)
      request = Google::Apis::LoggingV2::WriteLogEntriesRequest.new(
        log_name: log_name,
        resource: resource,
        labels: labels,
        entries: entries
      )
      @requests_received << request
      WriteLogEntriesResponse.new
    end
  end

  # GRPC logging mock that fails and returns server side or client side errors.
  class GRPCLoggingMockFailingService <
      Google::Cloud::Logging::V2::LoggingServiceV2Client
    def initialize(code, message, failed_attempts)
      @code = code
      @message = message
      @failed_attempts = failed_attempts
      super()
    end

    # rubocop:disable Lint/UnusedMethodArgument
    def write_log_entries(entries, log_name: nil, resource: nil, labels: nil)
      @failed_attempts << 1
      begin
        raise GRPC::BadStatus.new_status_exception(@code, @message)
      rescue
        # Google::Gax::GaxError will wrap the latest thrown exception as @cause.
        raise Google::Gax::GaxError, @message
      end
    end
    # rubocop:enable Lint/UnusedMethodArgument
  end

  # Set up grpc stubs to mock the external calls.
  def setup_logging_stubs(should_fail = false, code = nil, message = nil)
    if should_fail
      @failed_attempts = []
      @grpc_stub = GRPCLoggingMockFailingService.new(
        code, message, @failed_attempts)
    else
      @requests_sent = []
      @grpc_stub = GRPCLoggingMockService.new(@requests_sent)
    end
    yield
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload', &block)
    @requests_sent.each do |request|
      @logs_sent << {
        'entries' => request.entries.map { |entry| JSON.parse(entry.to_json) },
        'labels' => request.labels,
        'resource' => request.resource,
        'logName' => request.log_name
      }
    end
    verify_json_log_entries(n, params, payload_type, &block)
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

  # Get the fields of the payload.
  def get_fields(payload)
    payload['fields']
  end

  # Get the value of a struct field.
  def get_struct(field)
    field['structValue']
  end

  # Get the value of a string field.
  def get_string(field)
    field['stringValue']
  end

  # Get the value of a number field.
  def get_number(field)
    field['numberValue']
  end

  # The null value.
  def null_value
    { 'nullValue' => 'NULL_VALUE' }
  end
end
