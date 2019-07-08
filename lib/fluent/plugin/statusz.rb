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

# Note: The table below doesn't include the following config params
# because they are deprecated: auth_method, private_key_email,
# private_key_passphrase, private_key_path.

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
      <tr><th>adjust_invalid_timestamps</th><td><%= plugin.adjust_invalid_timestamps %></td></tr>
      <tr><th>auth_method</th><td><%= plugin.auth_method %></td></tr>
      <tr><th>autoformat_stackdriver_trace</th><td><%= plugin.autoformat_stackdriver_trace %></td></tr>
      <tr><th>coerce_to_utf8</th><td><%= plugin.coerce_to_utf8 %></td></tr>
      <tr><th>detect_json</th><td><%= plugin.detect_json %></td></tr>
      <tr><th>detect_subservice</th><td><%= plugin.detect_subservice %></td></tr>
      <tr><th>enable_metadata_agent</th><td><%= plugin.enable_metadata_agent %></td></tr>
      <tr><th>enable_monitoring</th><td><%= plugin.enable_monitoring %></td></tr>
      <tr><th>http_request_key</th><td><%= plugin.http_request_key %></td></tr>
      <tr><th>insert_id_key</th><td><%= plugin.insert_id_key %></td></tr>
      <tr><th>k8s_cluster_location</th><td><%= plugin.k8s_cluster_location %></td></tr>
      <tr><th>k8s_cluster_name</th><td><%= plugin.k8s_cluster_name %></td></tr>
      <tr><th>kubernetes_tag_regexp</th><td><%= plugin.kubernetes_tag_regexp %></td></tr>
      <tr><th>label_map</th><td><%= plugin.label_map %></td></tr>
      <tr><th>labels_key</th><td><%= plugin.labels_key %></td></tr>
      <tr><th>labels</th><td><%= plugin.labels %></td></tr>
      <tr><th>logging_api_url</th><td><%= plugin.logging_api_url %></td></tr>
      <tr><th>metadata_agent_url</th><td><%= plugin.metadata_agent_url %></td></tr>
      <tr><th>monitoring_type</th><td><%= plugin.monitoring_type %></td></tr>
      <tr><th>non_utf8_replacement_string</th><td><%= plugin.non_utf8_replacement_string %></td></tr>
      <tr><th>operation_key</th><td><%= plugin.operation_key %></td></tr>
      <tr><th>partial_success</th><td><%= plugin.partial_success %></td></tr>
      <tr><th>project_id</th><td><%= plugin.project_id %></td></tr>
      <tr><th>require_valid_tags</th><td><%= plugin.require_valid_tags %></td></tr>
      <tr><th>source_location_key</th><td><%= plugin.source_location_key %></td></tr>
      <tr><th>span_id_key</th><td><%= plugin.span_id_key %></td></tr>
      <tr><th>split_logs_by_tag</th><td><%= plugin.split_logs_by_tag %></td></tr>
      <tr><th>statusz_port</th><td><%= plugin.statusz_port %></td></tr>
      <tr><th>subservice_name</th><td><%= plugin.subservice_name %></td></tr>
      <tr><th>trace_key</th><td><%= plugin.trace_key %></td></tr>
      <tr><th>trace_sampled_key</th><td><%= plugin.trace_sampled_key %></td></tr>
      <tr><th>use_aws_availability_zone</th><td><%= plugin.use_aws_availability_zone %></td></tr>
      <tr><th>use_grpc</th><td><%= plugin.use_grpc %></td></tr>
      <tr><th>use_metadata_service</th><td><%= plugin.use_metadata_service %></td></tr>
      <tr><th>vm_id</th><td><%= plugin.vm_id %></td></tr>
      <tr><th>vm_name</th><td><%= plugin.vm_name %></td></tr>
      <tr><th>zone</th><td><%= plugin.zone %></td></tr>
    </table>
  </body>
</html>
).freeze
# rubocop:enable LineLength
