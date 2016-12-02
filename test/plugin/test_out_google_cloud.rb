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

require 'google/apis'
require 'helper'
require 'json'
require 'mocha/test_unit'
require 'time'
require 'webmock/test_unit'

require_relative 'base_test'

# Unit tests for Google Cloud Logging plugin
class GoogleCloudOutputTest < GoogleCloudPluginBaseTest
  def test_configure_service_account_application_default
    verify_configure_service_account_application_default(method(:create_driver))
  end

  def test_configure_service_account_private_key
    verify_configure_service_account_private_key(method(:create_driver))
  end

  def test_configure_custom_metadata
    verify_configure_custom_metadata(method(:create_driver))
  end

  def test_configure_invalid_metadata_missing_parts
    verify_configure_invalid_metadata_missing_parts(method(:create_driver))
  end

  def test_metadata_loading
    verify_metadata_loading(method(:create_driver))
  end

  def test_managed_vm_metadata_loading
    verify_managed_vm_metadata_loading(method(:create_driver))
  end

  def test_gce_metadata_does_not_load_when_use_metadata_service_is_false
    verify_gce_metadata_does_not_load_when_use_metadata_service_is_false(
      method(:create_driver))
  end

  def test_gce_used_when_detect_subservice_is_false
    verify_gce_used_when_detect_subservice_is_false(method(:create_driver))
  end

  def test_metadata_overrides
    verify_metadata_overrides(method(:create_driver))
  end

  def test_ec2_metadata_requires_project_id
    verify_ec2_metadata_requires_project_id(method(:create_driver))
  end

  def test_ec2_metadata_project_id_from_credentials
    verify_ec2_metadata_project_id_from_credentials(method(:create_driver))
  end

  def test_one_log
    verify_one_log(method(:setup_logging_stubs),
                   method(:create_driver),
                   method(:verify_log_entries))
  end

  def test_one_log_with_json_credentials
    verify_one_log_with_json_credentials(method(:setup_logging_stubs),
                                         method(:create_driver),
                                         method(:verify_log_entries))
  end

  def test_one_log_with_invalid_json_credentials
    verify_one_log_with_invalid_json_credentials(
      method(:setup_logging_stubs), method(:create_driver))
  end

  def test_one_log_custom_metadata
    verify_one_log_custom_metadata(method(:setup_logging_stubs),
                                   method(:create_driver),
                                   method(:verify_log_entries))
  end

  def test_one_log_ec2
    verify_one_log_ec2(method(:setup_logging_stubs),
                       method(:create_driver),
                       method(:verify_log_entries))
  end

  def test_struct_payload_log
    verify_struct_payload_log(method(:setup_logging_stubs),
                              method(:create_driver),
                              method(:verify_log_entries))
  end

  def test_struct_payload_json_log
    verify_struct_payload_json_log(method(:setup_logging_stubs),
                                   method(:create_driver),
                                   method(:verify_log_entries))
  end

  def test_struct_payload_json_container_log
    verify_struct_payload_json_container_log(method(:setup_logging_stubs),
                                             method(:create_driver),
                                             method(:verify_log_entries))
  end

  def test_timestamps
    verify_timestamps(method(:setup_logging_stubs),
                      method(:create_driver),
                      method(:verify_log_entries))
  end

  def test_malformed_timestamp
    verify_malformed_timestamp(method(:setup_logging_stubs),
                               method(:create_driver),
                               method(:verify_log_entries))
  end

  def test_severities
    verify_severities(method(:setup_logging_stubs),
                      method(:create_driver),
                      method(:verify_log_entries))
  end

  def test_label_map_without_field_present
    verify_label_map_without_field_present(method(:setup_logging_stubs),
                                           method(:create_driver),
                                           method(:verify_log_entries))
  end

  def test_label_map_with_field_present
    verify_label_map_with_field_present(method(:setup_logging_stubs),
                                        method(:create_driver),
                                        method(:verify_log_entries))
  end

  def test_label_map_with_numeric_field
    verify_label_map_with_numeric_field(method(:setup_logging_stubs),
                                        method(:create_driver),
                                        method(:verify_log_entries))
  end

  def test_label_map_with_hash_field
    verify_label_map_with_hash_field(method(:setup_logging_stubs),
                                     method(:create_driver),
                                     method(:verify_log_entries))
  end

  def test_label_map_with_multiple_fields
    verify_label_map_with_multiple_fields(method(:setup_logging_stubs),
                                          method(:create_driver),
                                          method(:verify_log_entries))
  end

  def test_multiple_logs
    verify_multiple_logs(method(:setup_logging_stubs),
                         method(:create_driver),
                         method(:verify_log_entries))
  end

  def test_malformed_log
    verify_malformed_log(method(:setup_logging_stubs),
                         method(:create_driver))
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

  def test_one_managed_vm_log
    verify_one_managed_vm_log(method(:setup_logging_stubs),
                              method(:create_driver),
                              method(:verify_log_entries))
  end

  def test_multiple_managed_vm_logs
    verify_multiple_managed_vm_logs(method(:setup_logging_stubs),
                                    method(:create_driver),
                                    method(:verify_log_entries))
  end

  def test_one_container_log_metadata_from_plugin
    verify_one_container_log_metadata_from_plugin(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_multiple_container_logs_metadata_from_plugin
    verify_multiple_container_logs_metadata_from_plugin(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_multiple_container_logs_metadata_from_tag
    verify_multiple_container_logs_metadata_from_tag(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_one_container_log_metadata_from_tag
    verify_one_container_log_metadata_from_tag(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_one_container_log_from_tag_stderr
    verify_one_container_log_from_tag_stderr(method(:setup_logging_stubs),
                                             method(:create_driver),
                                             method(:verify_log_entries))
  end

  def test_struct_container_log_metadata_from_plugin
    verify_struct_container_log_metadata_from_plugin(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_struct_container_log_metadata_from_tag
    verify_struct_container_log_metadata_from_tag(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_cloudfunctions_log
    verify_cloudfunctions_log(method(:setup_logging_stubs),
                              method(:create_driver),
                              method(:verify_log_entries))
  end

  def test_cloudfunctions_logs_text_not_matched
    verify_cloudfunctions_logs_text_not_matched(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_multiple_cloudfunctions_logs_tag_not_matched
    verify_multiple_cloudfunctions_logs_tag_not_matched(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_http_request_from_record
    verify_http_request_from_record(method(:setup_logging_stubs),
                                    method(:create_driver),
                                    method(:verify_log_entries))
  end

  def test_http_request_partial_from_record
    verify_http_request_partial_from_record(method(:setup_logging_stubs),
                                            method(:create_driver),
                                            method(:verify_log_entries))
  end

  def test_http_request_without_referer_from_record
    verify_http_request_without_referer_from_record(
      method(:setup_logging_stubs), method(:create_driver),
      method(:verify_log_entries))
  end

  def test_http_request_when_not_hash
    verify_http_request_when_not_hash(method(:setup_logging_stubs),
                                      method(:create_driver),
                                      method(:verify_log_entries))
  end

  # Make parse_severity public so we can test it.
  class Fluent::GoogleCloudOutput # rubocop:disable Style/ClassAndModuleChildren
    public :parse_severity
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
end
