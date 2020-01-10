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

module Fluent
  # GkeFilter modifies the records for GKE's needs.
  class GkeFilter < Filter
    Fluent::Plugin.register_filter('gke', self)

    config_param :mode, :string, default: nil

    def configure(conf)
      super

      raise Fluent::ConfigError, 'must set mode' if @mode.nil?
    end

    def filter(tag, time, record)
      case mode
      when '1'
        return filter_mode1(tag, time, record)
      when '2'
        return filter_mode2(tag, time, record)
      when '3'
        return filter_mode3(tag, time, record)
      else
        # This should probably raise an exception.
        record
      end
    end

    def filter_mode1(_tag, _time, record)
      # Extract "kubernetes"->"labels" and set them as
      # "logging.googleapis.com/labels". Prefix these labels with
      # "k8s-pod-labels" to distinguish with other labels and avoid
      # label name collision with other types of labels.
      if record.is_a?(Hash) && record.key?('kubernetes') && record['kubernetes'].key?('labels') && record['kubernetes']['labels'].is_a?(Hash)
        record['logging.googleapis.com/labels'] = record['kubernetes']['labels'].map { |k, v| ["k8s-pod-label/#{k}", v] }.to_h
      end
      record.delete('kubernetes')
      record.delete('docker')

      # Extract local_resource_id from tag for 'k8s_container' monitored
      # resource. The format is:
      # 'k8s_container.<namespace_name>.<pod_name>.<container_name>'.
      # tag_suffix comes from record_reformer and can probably be simplified.
      tag_parts = tag.split('.')
      tag_suffix = tag_suffix(tag_parts)
      record['logging.googleapis.com/local_resource_id'] = "k8s_container.#{tag_suffix[4].rpartition('.')[0].split('_')[1]}.#{tag_suffix[4].rpartition('.')[0].split('_')[0]}.#{tag_suffix[4].rpartition('.')[0].split('_')[2].rpartition('-')[0]}"
      # Rename the field 'log' to a more generic field 'message'. This way the
      # fluent-plugin-google-cloud knows to flatten the field as textPayload
      # instead of jsonPayload after extracting 'time', 'severity' and
      # 'stream' from the record.
      record['message'] = record['log']
      # If 'severity' is not set, assume stderr is ERROR and stdout is INFO.
      record['severity'] ||= if record['stream'] == 'stderr' then 'ERROR' else 'INFO' end
      record.delete('log')
      record.delete('stream')
      record
    end

    def filter_mode2(_tag, _time, record)
      # TODO(instrumentation): Reconsider this workaround later.
      # Trim the entries which exceed slightly less than 100KB, to avoid
      # dropping them. It is a necessity, because Stackdriver only supports
      # entries that are up to 100KB in size.
      record['message'] = "[Trimmed]#{record['message'][0..100000]}..." if record['message'].length > 100000
      # This filter parses the 'source' field created for glog lines into a single
      # top-level field, for proper processing by the output plugin.
      # For example, if a record includes:
      #     {"source":"handlers.go:131"},
      # then the following entry will be added to the record:
      #     {"logging.googleapis.com/sourceLocation":
      #          {"file":"handlers.go", "line":"131"}
      #     }
      if record.is_a?(Hash) && record.key?('source')
        source_parts = record['source'].split(':', 2)
        record['logging.googleapis.com/sourceLocation'] = {'file' => source_parts[0], 'line' => source_parts[1]} if source_parts.length == 2
      end
      record
    end

    def filter_mode3(_tag, _time, record)
      # Attach local_resource_id for 'k8s_node' monitored resource.
      record['logging.googleapis.com/local_resource_id'] = "k8s_node.#{ENV['NODE_NAME']}"
      record
    end

    private

    def tag_suffix(tag_parts)
      return [] if tag_parts.empty?
      rev_tag_parts = tag_parts.reverse
      rev_tag_suffix = [rev_tag_parts.first]
      1.upto(tag_parts.size-1).each do |i|
        rev_tag_suffix[i] = "#{rev_tag_parts[i]}.#{rev_tag_suffix[i-1]}"
      end
      rev_tag_suffix.reverse!
    end
  end
end
