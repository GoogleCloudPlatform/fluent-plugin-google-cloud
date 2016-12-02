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

require 'google/apis'
require 'grpc'
require 'helper'
require 'json'
require 'mocha/test_unit'
require 'time'
require 'webmock/test_unit'

require_relative 'base_test'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputGRPCTest < GoogleCloudPluginBaseTest
  def test_configure_service_account_application_default
    verify_configure_service_account_application_default(
      method(:create_grpc_driver))
  end

  def test_configure_service_account_private_key
    verify_configure_service_account_private_key(method(:create_grpc_driver))
  end

  def test_configure_custom_metadata
    verify_configure_custom_metadata(method(:create_grpc_driver))
  end

  def test_configure_invalid_metadata_missing_parts
    verify_configure_invalid_metadata_missing_parts(method(:create_grpc_driver))
  end

  def test_metadata_loading
    verify_metadata_loading(method(:create_grpc_driver))
  end

  def test_managed_vm_metadata_loading
    verify_managed_vm_metadata_loading(method(:create_grpc_driver))
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false
    verify_gce_metadata_does_not_load_when_use_metadata_service_is_false(
      method(:create_grpc_driver))
  end

  def test_gce_used_when_detect_subservice_is_false
    verify_gce_used_when_detect_subservice_is_false(method(:create_grpc_driver))
  end

  def test_configure_use
    setup_gce_metadata_stubs
    { create_driver => false,
      create_grpc_driver => true }.each do |driver, value|
      assert_equal value, driver.instance.instance_variable_get(:@use_grpc)
    end
  end

  def test_metadata_overrides
    verify_metadata_overrides(method(:create_grpc_driver))
  end

  def test_ec2_metadata_requires_project_id
    verify_ec2_metadata_requires_project_id(method(:create_grpc_driver))
  end

  def test_ec2_metadata_project_id_from_credentials
    verify_ec2_metadata_project_id_from_credentials(method(:create_grpc_driver))
  end

  def test_one_log
    verify_one_log(method(:setup_grpc_logging_stubs),
                   method(:create_grpc_driver),
                   method(:verify_grpc_log_entries))
  end

  def test_one_log_with_json_credentials
    verify_one_log_with_json_credentials(method(:setup_grpc_logging_stubs),
                                         method(:create_grpc_driver),
                                         method(:verify_grpc_log_entries))
  end

  def test_one_log_with_invalid_json_credentials
    verify_one_log_with_invalid_json_credentials(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver))
  end

  def test_one_log_custom_metadata
    verify_one_log_custom_metadata(method(:setup_grpc_logging_stubs),
                                   method(:create_grpc_driver),
                                   method(:verify_grpc_log_entries))
  end

  def test_one_log_ec2
    verify_one_log_ec2(method(:setup_grpc_logging_stubs),
                       method(:create_grpc_driver),
                       method(:verify_grpc_log_entries))
  end

  def test_struct_payload_log
    verify_struct_payload_log(method(:setup_grpc_logging_stubs),
                              method(:create_grpc_driver),
                              method(:verify_grpc_log_entries))
  end

  def test_struct_payload_json_log
    verify_struct_payload_json_log(method(:setup_grpc_logging_stubs),
                                   method(:create_grpc_driver),
                                   method(:verify_grpc_log_entries))
  end

  def test_struct_payload_json_container_log
    verify_struct_payload_json_container_log(method(:setup_grpc_logging_stubs),
                                             method(:create_grpc_driver),
                                             method(:verify_grpc_log_entries))
  end

  def test_timestamps
    verify_timestamps(method(:setup_grpc_logging_stubs),
                      method(:create_grpc_driver),
                      method(:verify_grpc_log_entries))
  end

  def test_malformed_timestamp
    verify_malformed_timestamp(method(:setup_grpc_logging_stubs),
                               method(:create_grpc_driver),
                               method(:verify_grpc_log_entries))
  end

  def test_severities
    verify_severities(method(:setup_grpc_logging_stubs),
                      method(:create_grpc_driver),
                      method(:verify_grpc_log_entries))
  end

  def test_label_map_without_field_present
    verify_label_map_without_field_present(method(:setup_grpc_logging_stubs),
                                           method(:create_grpc_driver),
                                           method(:verify_grpc_log_entries))
  end

  def test_label_map_with_field_present
    verify_label_map_with_field_present(method(:setup_grpc_logging_stubs),
                                        method(:create_grpc_driver),
                                        method(:verify_grpc_log_entries))
  end

  def test_label_map_with_numeric_field
    verify_label_map_with_numeric_field(method(:setup_grpc_logging_stubs),
                                        method(:create_grpc_driver),
                                        method(:verify_grpc_log_entries))
  end

  def test_label_map_with_hash_field
    verify_label_map_with_hash_field(method(:setup_grpc_logging_stubs),
                                     method(:create_grpc_driver),
                                     method(:verify_grpc_log_entries))
  end

  def test_label_map_with_multiple_fields
    verify_label_map_with_multiple_fields(method(:setup_grpc_logging_stubs),
                                          method(:create_grpc_driver),
                                          method(:verify_grpc_log_entries))
  end

  def test_multiple_logs
    verify_multiple_logs(method(:setup_grpc_logging_stubs),
                         method(:create_grpc_driver),
                         method(:verify_grpc_log_entries))
  end

  def test_malformed_log
    verify_malformed_log(method(:setup_grpc_logging_stubs),
                         method(:create_grpc_driver))
  end

  def test_client_error
    setup_gce_metadata_stubs
    { 8 => 'ResourceExhausted',
      12 => 'Unimplemented',
      16 => 'Unauthenticated' }.each_with_index do |(code, message), index|
      setup_grpc_logging_stubs(true, code, message) do
        d = create_grpc_driver(USE_GRPC_CONFIG, 'test',
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
      setup_grpc_logging_stubs(true, code, message) do
        d = create_grpc_driver(USE_GRPC_CONFIG, 'test',
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

  def test_one_managed_vm_log
    verify_one_managed_vm_log(method(:setup_grpc_logging_stubs),
                              method(:create_grpc_driver),
                              method(:verify_grpc_log_entries))
  end

  def test_multiple_managed_vm_logs
    verify_multiple_managed_vm_logs(method(:setup_grpc_logging_stubs),
                                    method(:create_grpc_driver),
                                    method(:verify_grpc_log_entries))
  end

  def test_one_container_log_metadata_from_plugin
    verify_one_container_log_metadata_from_plugin(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_multiple_container_logs_metadata_from_plugin
    verify_multiple_container_logs_metadata_from_plugin(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_multiple_container_logs_metadata_from_tag
    verify_multiple_container_logs_metadata_from_tag(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_one_container_log_metadata_from_tag
    verify_one_container_log_metadata_from_tag(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_one_container_log_from_tag_stderr
    verify_one_container_log_from_tag_stderr(method(:setup_grpc_logging_stubs),
                                             method(:create_grpc_driver),
                                             method(:verify_grpc_log_entries))
  end

  def test_struct_container_log_metadata_from_plugin
    verify_struct_container_log_metadata_from_plugin(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_struct_container_log_metadata_from_tag
    verify_struct_container_log_metadata_from_tag(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_cloudfunctions_log
    verify_cloudfunctions_log(method(:setup_grpc_logging_stubs),
                              method(:create_grpc_driver),
                              method(:verify_grpc_log_entries))
  end

  def test_cloudfunctions_logs_text_not_matched
    verify_cloudfunctions_logs_text_not_matched(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_multiple_cloudfunctions_logs_tag_not_matched
    verify_multiple_cloudfunctions_logs_tag_not_matched(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_http_request_from_record
    verify_http_request_from_record(method(:setup_grpc_logging_stubs),
                                    method(:create_grpc_driver),
                                    method(:verify_grpc_log_entries))
  end

  def test_http_request_partial_from_record
    verify_http_request_partial_from_record(method(:setup_grpc_logging_stubs),
                                            method(:create_grpc_driver),
                                            method(:verify_grpc_log_entries))
  end

  def test_http_request_without_referer_from_record
    verify_http_request_without_referer_from_record(
      method(:setup_grpc_logging_stubs), method(:create_grpc_driver),
      method(:verify_grpc_log_entries))
  end

  def test_http_request_when_not_hash
    verify_http_request_when_not_hash(method(:setup_grpc_logging_stubs),
                                      method(:create_grpc_driver),
                                      method(:verify_grpc_log_entries))
  end
end
