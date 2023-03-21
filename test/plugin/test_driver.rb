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

require 'fluent/engine'
require 'fluent/event'
require 'fluent/test/input_test'

module Fluent
  module Test
    # Similar to the standard BufferedOutputTestDriver, but allows multiple tags
    # to exist in one chunk.
    class MultiTagBufferedOutputTestDriver < InputTestDriver
      def initialize(klass, &block)
        super(klass, &block)
        @entries = []
      end

      def emit(tag, record, time = Engine.now)
        es = ArrayEventStream.new([[time, record]])
        data = @instance.format_stream(tag, es)
        @entries << data
        self
      end

      def run(num_waits = 10)
        result = nil
        super(num_waits) do
          chunk = @instance.buffer.generate_chunk(
            @instance.metadata(nil, nil, nil)
          ).staged!
          @entries.each do |entry|
            chunk.concat(entry, 1)
          end

          begin
            result = @instance.write(chunk)
          ensure
            chunk.purge
          end
        end
        result
      end
    end
  end
end
