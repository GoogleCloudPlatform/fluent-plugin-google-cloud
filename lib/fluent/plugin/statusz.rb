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

require 'erb'

# Module for collecting diagnostic information and formatting it as an
# HTML page to serve on the /statusz endpoint.
module Statusz
  module_function

  # Note: The plugin parameter is referenced in STATUSZ_TMPL.
  def response(plugin)
    uptime = Time.now - SERVER_START
    uptime_str = format('%d hr %02d min %02d sec',
                        uptime / 3600,
                        (uptime / 60) % 60,
                        uptime % 60)
    ERB.new(STATUSZ_TMPL).result(binding)
  end
end

SERVER_START = Time.now

# Does not include the following deprecated config params:
# auth_method, private_key_email, private_key_passphrase, private_key_path
CONFIG_KEYS = %w(
  adjust_invalid_timestamps
  autoformat_stackdriver_trace
  coerce_to_utf8
  detect_json
  detect_subservice
  enable_monitoring
  http_request_key
  insert_id_key
  k8s_cluster_location
  k8s_cluster_name
  kubernetes_tag_regexp
  label_map
  labels_key
  labels
  logging_api_url
  monitoring_type
  non_utf8_replacement_string
  operation_key
  project_id
  require_valid_tags
  source_location_key
  span_id_key
  split_logs_by_tag
  statusz_port
  subservice_name
  trace_key
  trace_sampled_key
  use_aws_availability_zone
  use_grpc
  use_metadata_service
  vm_id
  vm_name
  zone
).freeze

# rubocop:disable LineLength
STATUSZ_TMPL = %(\
<!DOCTYPE html>
<html>
  <head>
    <title>Status for <%= File.basename($PROGRAM_NAME) %></title>
    <style>
      body {
        font-family: sans-serif;
      }
      h1 {
        clear: both;
        width: 100%;
        text-align: center;
        font-size: 120%;
        background: #eef;
      }
      .lefthand {
        float: left;
        width: 80%;
      }
      .righthand {
        text-align: right;
      }
      td, th {
        background-color: rgba(0, 0, 0, 0.05);
      }
      th {
        text-align: left;
      }
    </style>
  </head>

  <body>
    <h1>Status for <%= File.basename($PROGRAM_NAME) %></h1>

    <div>
      <div class="lefthand">
        Started: <%= SERVER_START %><br>
        Up <%= uptime_str %><br>
      </div>
    </div>

    <h1>Parsed configuration</h1>

    <table>
#{CONFIG_KEYS.map { |k| "      <tr><th>#{k}</th><td><%= plugin.#{k} %></td></tr>" }.join("\n")}
    </table>
  </body>
</html>
).freeze
# rubocop:enable LineLength
