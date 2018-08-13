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

require 'fluent/plugin/filter'
require 'thread'

module Fluent
  module Plugin
    # Fluentd filter plugin for adding insertIds to guarantee log entry order
    # and uniqueness.
    class AddInsertIdsFilter < Filter
      Fluent::Plugin.register_filter('add_insert_ids', self)

      # Constants for configuration.
      module ConfigConstants
        # The default field name of insertIds in the log entry.
        DEFAULT_INSERT_ID_KEY = 'logging.googleapis.com/insertId'.freeze
        # The character size of the insertIds. This matches the setup in the
        # Stackdriver Logging backend.
        INSERT_ID_SIZE = 17
        # The characters that are allowed in the insertIds. This matches the
        # allowed collection by the Stackdriver Logging Backend.
        ALLOWED_CHARS = (Array(0..9) + Array('a'..'z')).freeze
      end

      include self::ConfigConstants

      desc 'The field name of insertIds in the log entry.'
      config_param :insert_id_key, :string, default: DEFAULT_INSERT_ID_KEY

      # Expose attr_readers to make testing of metadata more direct than only
      # testing it indirectly through metadata sent with logs.
      attr_reader :insert_id_key

      def start
        super
        @log = $log # rubocop:disable Style/GlobalVars

        # Initiate the insertID.
        @log.info "Started the add_insert_ids plugin with #{@insert_id_key}" \
                  ' as the insert ID key.'
        @insert_id = generate_insert_id
        @log.info "Initiated the insert ID key at #{@insert_id}."
      end

      def configure(conf)
        super
      end

      def shutdown
        super
      end

      # rubocop:disable Style/UnusedMethodArgument
      def filter(tag, time, record)
        # Only generate and add an insertId field If the record is a hash and
        # the insert ID field is not already set.
        if record.is_a?(Hash) && !record.key?(@insert_id_key)
          record[@insert_id_key] = increment_insert_id
        end
        record
      end
      # rubocop:enable Style/UnusedMethodArgument

      private

      # Generates a random string as the insertId.
      def generate_insert_id
        Array.new(INSERT_ID_SIZE) { ALLOWED_CHARS.sample }.join
      end

      # Increment the insertId and return the new value.
      def increment_insert_id
        @insert_id = @insert_id.next
      end
    end
  end
end
