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
  include Fluent::Plugin::AddInsertIdsFilter::ConfigConstants

  CUSTOM_INSERT_ID_KEY = 'custom_insert_id_key'.freeze
  APPLICATION_DEFAULT_CONFIG = ''.freeze
  TEST_MESSAGE = 'test message for add_insert_ids plugin.'.freeze
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
    filtered_events.each_with_index do |event, index|
      assert_equal 3, event.size, "Index #{index} failed. Log event should" \
                   ' include 3 elements: tag, time and record.'
      record = event[2]
      assert_true record.is_a?(Hash), "Index #{index} failed. Log record" \
                  ' should be a hash.'
      assert_equal index, record['id'], "Index #{index} failed."
      assert_equal TEST_MESSAGE, record['message'], "Index #{index} failed."

      # Get the first insertID.
      expected_insert_id = record[DEFAULT_INSERT_ID_KEY] if index == 0
      assert_equal expected_insert_id, record[DEFAULT_INSERT_ID_KEY],
                   "Index #{index} failed."
      expected_insert_id = expected_insert_id.next
      assert_true record[DEFAULT_INSERT_ID_KEY] < expected_insert_id,
                  "Index #{index} failed. #{record[DEFAULT_INSERT_ID_KEY]}" \
                  " < #{expected_insert_id} is false."
    end
  end

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::FilterTestDriver.new(
      Fluent::Plugin::AddInsertIdsFilter).configure(conf, true)
  end

  def log_entry(index)
    {
      'id' => index,
      'message' => TEST_MESSAGE
    }
  end
end
