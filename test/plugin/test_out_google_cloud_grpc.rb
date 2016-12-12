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
      assert_equal_with_default(entry['metadata']['severity'],
                                expected_severity[verify_index],
                                'DEFAULT', entry)
      verify_index += 1
    end
  end

  private

  GRPC_MOCK_HOST = 'localhost:56789'

  WriteLogEntriesRequest = Google::Logging::V1::WriteLogEntriesRequest
  WriteLogEntriesResponse = Google::Logging::V1::WriteLogEntriesResponse

  USE_GRPC_CONFIG = %(
    use_grpc true
  )

  # The non-grpc path has a unique field 'validatedWithOriginServer', while
  # the grpc path has a unique field 'cacheValidatedWithOriginServer'.
  HTTP_REQUEST_MESSAGE = {
    'requestMethod' => 'POST',
    'requestUrl' => 'http://example/',
    'requestSize' => 210,
    'status' => 200,
    'responseSize' => 65,
    'userAgent' => 'USER AGENT 1.0',
    'remoteIp' => '55.55.55.55',
    'referer' => 'http://referer/',
    'cacheHit' => true,
    'cacheValidatedWithOriginServer' => true
  }

  # In the non-grpc path 'referer' is nil, while in the grpc path 'referer' is
  # absent.
  HTTP_REQUEST_MESSAGE_WITHOUT_REFERER = HTTP_REQUEST_MESSAGE.reject do |k, _|
    k == 'referer'
  end

  # Create a Fluentd output test driver with the Google Cloud Output plugin with
  # grpc enabled. The signature of this method is different between the grpc
  # path and the non-grpc path. For grpc, an additional grpc stub class can be
  #  passed in to construct the mock used by the test driver.
  def create_driver(conf = APPLICATION_DEFAULT_CONFIG, tag = 'test',
                    grpc_stub = GRPCLoggingMockService.rpc_stub_class)
    conf += USE_GRPC_CONFIG
    Fluent::Test::BufferedOutputTestDriver.new(
      GoogleCloudOutputWithGRPCMock.new(grpc_stub), tag).configure(
        conf, use_v1_config: true)
  end

  # Google Cloud Fluent output stub with grpc mock.
  class GoogleCloudOutputWithGRPCMock < Fluent::GoogleCloudOutput
    def initialize(grpc_stub)
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
  class GRPCLoggingMockService < Google::Logging::V1::LoggingService::Service
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
    alias_method :list_log_services, :_undefined
    alias_method :list_log_service_indexes, :_undefined
    alias_method :delete_log, :_undefined
    undef_method :_undefined
  end

  # GRPC logging mock that fails and returns server side or client side errors.
  class GRPCLoggingMockFailingService <
      Google::Logging::V1::LoggingService::Service
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
    alias_method :list_log_services, :_undefined
    alias_method :list_log_service_indexes, :_undefined
    alias_method :delete_log, :_undefined
    undef_method :_undefined
  end

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

  # The caller can optionally provide a block which is called for each entry.
  def verify_log_entries(n, params, payload_type = 'textPayload', &block)
    @requests_sent.each do |batch|
      @logs_sent << JSON.parse(batch.to_json)
    end
    verify_json_log_entries(n, params, payload_type, &block)
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
    else
      assert_equal expected_value, field, entry
    end
  end

  # This method is just a simple wrapper around a constant, so the definition
  # can be skipped in the shared module and defined in the test class later.
  def http_request_message
    HTTP_REQUEST_MESSAGE
  end

  # This method is just a simple wrapper around a constant, so the definition
  # can be skipped in the shared module and defined in the test class later.
  def http_request_message_without_referer
    HTTP_REQUEST_MESSAGE_WITHOUT_REFERER
  end

  def get_fields(struct_payload)
    struct_payload['fields']
  end

  def get_struct(field)
    field['structValue']
  end

  def get_string(field)
    field['stringValue']
  end

  def get_number(field)
    field['numberValue']
  end
end
