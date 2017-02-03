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
    { 8 => 'ResourceExhausted',
      12 => 'Unimplemented',
      16 => 'Unauthenticated' }.each_with_index do |(code, message), index|
      setup_logging_stubs(true, code, message) do
        d = create_driver(USE_GRPC_CONFIG, 'test',
                          GRPCLoggingMockFailingService.rpc_stub_class)
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
    { 1 => 'Cancelled',
      2 => 'Unknown',
      4 => 'DeadlineExceeded',
      13 => 'Internal',
      14 => 'Unavailable' }.each_with_index do |(code, message), index|
      exception_count = 0
      setup_logging_stubs(true, code, message) do
        d = create_driver(USE_GRPC_CONFIG, 'test',
                          GRPCLoggingMockFailingService.rpc_stub_class)
        # The API client should retry this once, then throw an exception which
        # gets propagated through the plugin
        d.emit('message' => log_entry(0))
        begin
          d.run
        rescue GRPC::Cancelled => error
          assert_equal "GRPC::#{message}", error.message
          exception_count += 1
        rescue GRPC::BadStatus => error
          assert_equal "#{code}:#{message}", error.message
          exception_count += 1
        end
      end
      assert_equal 1, @failed_attempts.size, "Index #{index} failed."
      assert_equal 1, exception_count, "Index #{index} failed."
    end
  end

  def test_http_request_from_record_with_referer_nil
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => http_request_message_with_nil_referer)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal http_request_message_with_absent_referer,
                   entry['httpRequest'], entry
      assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
    end
  end

  def test_http_request_from_record_with_referer_absent
    setup_gce_metadata_stubs
    setup_logging_stubs do
      d = create_driver
      d.emit('httpRequest' => http_request_message_with_absent_referer)
      d.run
    end
    verify_log_entries(1, COMPUTE_PARAMS, 'httpRequest') do |entry|
      assert_equal http_request_message_with_absent_referer,
                   entry['httpRequest'], entry
      assert_nil get_fields(entry['jsonPayload'])['httpRequest'], entry
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

  GRPC_MOCK_HOST = 'localhost:56789'

  WriteLogEntriesRequest = Google::Logging::V2::WriteLogEntriesRequest
  WriteLogEntriesResponse = Google::Logging::V2::WriteLogEntriesResponse

  USE_GRPC_CONFIG = %(
    use_grpc true
  )

  # Create a Fluentd output test driver with the Google Cloud Output plugin with
  # grpc enabled. The signature of this method is different between the grpc
  # path and the non-grpc path. For grpc, an additional grpc stub class can be
  # passed in to construct the mock used by the test driver.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test',
                    grpc_stub = GRPCLoggingMockService.rpc_stub_class)
    conf += USE_GRPC_CONFIG
    Fluent::Test::BufferedOutputTestDriver.new(
      GoogleCloudOutputWithGRPCMock.new(grpc_stub), tag).configure(conf, true)
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

      # Here we have obtained the creds, but for the mock, we will leave the
      # channel insecure.
      @grpc_stub.new(GRPC_MOCK_HOST, :this_channel_is_insecure)
    end
  end

  # GRPC logging mock that successfully logs the records.
  class GRPCLoggingMockService < Google::Logging::V2::LoggingServiceV2::Service
    def initialize(requests_received)
      super()
      @requests_received = requests_received
    end

    def write_log_entries(request, _call)
      @requests_received << request
      WriteLogEntriesResponse.new
    end

    # TODO(lingshi) Remove these dummy methods when grpc/9033 is fixed.
    #
    # These methods should never be called, so they will just fail the tests
    # with "unimplemented" errors..
    def _undefined
      fail "Method #{__callee__} is unimplemented and needs to be overridden."
    end

    alias_method :list_logs, :_undefined
    alias_method :list_log_entries, :_undefined
    alias_method :list_log_services, :_undefined
    alias_method :list_log_service_indexes, :_undefined
    alias_method :list_monitored_resource_descriptors, :_undefined
    alias_method :delete_log, :_undefined
    undef_method :_undefined
  end

  # GRPC logging mock that fails and returns server side or client side errors.
  class GRPCLoggingMockFailingService <
      Google::Logging::V2::LoggingServiceV2::Service
    # 'code_sent' and 'message_sent' are references of external variables. We
    #  will assert the values of them later. 'code_value' and 'message_value'
    #  are actual error code and message we expect this mock to return.
    def initialize(code, message, failed_attempts)
      @code = code
      @message = message
      @failed_attempts = failed_attempts
      super()
    end

    def write_log_entries(_request, _call)
      @failed_attempts << 1
      fail GRPC::BadStatus.new(@code, @message)
    end

    # TODO(lingshi) Remove these dummy methods when grpc/9033 is fixed.
    #
    # These methods should never be called, so they will just fail the tests
    # with "unimplemented" errors..
    def _undefined
      fail "Method #{__callee__} is unimplemented and needs to be overridden."
    end

    alias_method :list_logs, :_undefined
    alias_method :list_log_entries, :_undefined
    alias_method :list_log_services, :_undefined
    alias_method :list_log_service_indexes, :_undefined
    alias_method :list_monitored_resource_descriptors, :_undefined
    alias_method :delete_log, :_undefined
    undef_method :_undefined
  end

  # Set up grpc stubs to mock the external calls.
  def setup_logging_stubs(should_fail = false, code = 0, message = 'Ok')
    srv = GRPC::RpcServer.new
    @failed_attempts = []
    @requests_sent = []
    if should_fail
      grpc = GRPCLoggingMockFailingService.new(code, message, @failed_attempts)
    else
      grpc = GRPCLoggingMockService.new(@requests_sent)
    end
    srv.handle(grpc)
    srv.add_http2_port(GRPC_MOCK_HOST, :this_port_is_insecure)
    t = Thread.new { srv.run }
    srv.wait_till_running
    begin
      yield
    rescue Test::Unit::Failure, StandardError => e
      srv.stop
      t.join
      raise e
    end
    srv.stop
    t.join
  end

  # Verify the number and the content of the log entries match the expectation.
  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload', &block)
    @requests_sent.each do |request|
      @logs_sent << JSON.parse(request.to_json)
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

  # Unset the 'referer' field.
  def http_request_message_with_absent_referer
    HTTP_REQUEST_MESSAGE.reject do |k, _|
      k == 'referer'
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
