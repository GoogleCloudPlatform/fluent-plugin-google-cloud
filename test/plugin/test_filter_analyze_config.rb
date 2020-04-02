# Copyright 2020 Google Inc. All rights reserved.
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
require 'fluent/plugin/filter_analyze_config'

# Unit tests for filter_analyze_config plugin.
class FilterAnalyzeConfigTest < Test::Unit::TestCase
  include Fluent::AnalyzeConfigFilter::Constants

  APPLICATION_DEFAULT_CONFIG = ''.freeze

  def setup
    Fluent::Test.setup
  end

  def test_config_file_does_not_exist
    # By default, the FilterTestDriver.new does not set up a config file at:
    # /etc/google-fluentd/google-fluentd.conf. The plugin should still proceed.
    create_driver
    # No exceptions were thrown.
  end

  def test_analyze_config
    # TODO
  end

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::FilterTestDriver.new(
      Fluent::AnalyzeConfigFilter).configure(conf, true)
  end
end
