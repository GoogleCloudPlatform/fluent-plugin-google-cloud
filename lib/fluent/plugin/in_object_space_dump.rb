# Copyright 2019 Google Inc. All rights reserved.
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
require 'fluent/plugin/input'
require 'objspace'

module Fluent
  # Dump out all live objects to a json file.
  class ObjectSpaceDumpInput < Fluent::Plugin::Input
    Fluent::Plugin.register_input('object_space_dump', self)

    helpers :timer

    def initialize
      super

      ObjectSpace.trace_object_allocations_start
    end

    # These files are large. If you increase this interval, make sure you have
    # enough disk space.
    config_param :emit_interval, :time, default: 3600

    def multi_workers_ready?
      true
    end

    def start
      super

      # Dump during startup. The timer only fires after @emit_interval.
      on_timer
      timer_execute(:object_space_dump_input, @emit_interval,
                    &method(:on_timer))
    end

    def on_timer
      GC.start
      # The create method doesn't delete the file.
      file = Tempfile.create(['heap', '.json'])
      begin
        log.info 'dumping object space to', filepath: file.path
        ObjectSpace.dump_all(output: file)
      ensure
        file.close
      end
    end
  end
end
