# Copyright 2018 Google Inc. All rights reserved.
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

require_relative '../helper'

require 'fluent/test/driver/filter'
require 'fluent/plugin/filter_add_insert_ids'

# Unit tests for filter_add_insert_ids plugin.
class FilterAddInsertIdsTest < Test::Unit::TestCase
  include Fluent::AddInsertIdsFilter::ConfigConstants

  CUSTOM_INSERT_ID_KEY = 'custom_insert_id_key'.freeze
  INSERT_ID = 'aeyr82r92h249gh9h'.freeze
  TEST_MESSAGE = 'test message for add_insert_ids plugin.'.freeze
  APPLICATION_DEFAULT_CONFIG = ''.freeze
  INSERT_ID_KEY_CONFIG = %(
    insert_id_key #{CUSTOM_INSERT_ID_KEY}
  ).freeze

  def setup
    Fluent::Test.setup
  end

  def test_configure_insert_id_key
    {
      APPLICATION_DEFAULT_CONFIG => DEFAULT_INSERT_ID_KEY,
      INSERT_ID_KEY_CONFIG => CUSTOM_INSERT_ID_KEY
    }.each do |config, insert_id_key|
      d = create_driver(config)
      assert_equal insert_id_key, d.instance.insert_id_key
    end
  end

  def test_add_insert_ids
    total_entry_count = 1000
    d = create_driver
    d.run do
      total_entry_count.times do |index|
        d.emit(log_entry(index))
      end
    end
    filtered_events = d.filtered_as_array

    assert_equal total_entry_count, filtered_events.size,
                 "#{total_entry_count} log entries after filtering is" \
                 " expected. Only #{filtered_events.size} are detected."
    # The expected insertId will be assigned as we scan the first log entry.
    expected_insert_id = nil
    unique_insert_ids = Set.new
    filtered_events.each_with_index do |event, index|
      assert_equal 3, event.size, "Index #{index} failed. Log event should" \
                   ' include 3 elements: tag, time and record.'
      record = event[2]
      assert_true record.is_a?(Hash), "Index #{index} failed. Log record" \
                  " #{record} should be a hash."
      assert_equal index, record['id'], "Index #{index} failed. Log entries" \
                   ' should come in order.'
      assert_equal TEST_MESSAGE, record['message'], "Index #{index} failed."

      # Get the first insertID.
      expected_insert_id = record[DEFAULT_INSERT_ID_KEY] if index == 0
      insert_id = record[DEFAULT_INSERT_ID_KEY]
      assert_equal expected_insert_id, insert_id, "Index #{index} failed."
      expected_insert_id = expected_insert_id.next
      assert_true insert_id < expected_insert_id,
                  "Index #{index} failed. #{insert_id}" \
                  " < #{expected_insert_id} is false."
      unique_insert_ids << insert_id
    end
    assert_equal total_entry_count, unique_insert_ids.size,
                 "Expected #{total_entry_count} unique insertIds." \
                 " Only #{unique_insert_ids.size} found."
  end

  def test_insert_ids_not_added_if_present
    log_entry_with_empty_insert_id = log_entry(0).merge(
      DEFAULT_INSERT_ID_KEY => '')
    {
      log_entry(0).merge(DEFAULT_INSERT_ID_KEY => INSERT_ID) => true,
      # Still generate insertId if it's an empty string
      log_entry_with_empty_insert_id => false
    }.each do |test_data|
      input_log_entry, retain_original_insert_id = test_data
      # Make a copy because the log entry gets modified by the filter plugin.
      log_entry = input_log_entry.dup
      d = create_driver
      d.run do
        d.emit(log_entry)
      end
      filtered_events = d.filtered_as_array

      assert_equal 1, filtered_events.size, 'Exact 1 log entry after' \
                   " filtering is expected. Test data: #{test_data}."
      event = filtered_events[0]
      assert_equal 3, event.size, 'Log event should include 3 elements: tag,' \
                   " time and record. Test data: #{test_data}."
      record = event[2]
      assert_true record.is_a?(Hash), "Log record #{record} should be a hash." \
                  " Test data: #{test_data}."
      assert_equal 0, record['id'], "Test data: #{test_data}."
      assert_equal TEST_MESSAGE, record['message'], "Test data: #{test_data}."
      insert_id = record[DEFAULT_INSERT_ID_KEY]
      assert_false insert_id.to_s.empty?, 'Insert ID should not be empty.' \
                   " Test data: #{test_data}."
      assert_equal retain_original_insert_id,
                   input_log_entry[DEFAULT_INSERT_ID_KEY] == insert_id,
                   "Input value is #{input_log_entry[DEFAULT_INSERT_ID_KEY]}." \
                   " Output value is #{insert_id}. Test data: #{test_data}."
    end
  end

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::FilterTestDriver.new(
      Fluent::AddInsertIdsFilter).configure(conf, true)
  end

  def log_entry(index)
    {
      'id' => index,
      'message' => TEST_MESSAGE
    }
  end
end
