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

# Additional assert functions.
module Asserts
  # For an optional field with default values, Protobuf omits the field when it
  # is deserialized to json. So we need to add an extra check for gRPC which
  # uses Protobuf.
  #
  # An optional block can be passed in if we need to assert something other than
  # a plain equal. e.g. assert_in_delta.
  def assert_equal_with_default(_field, _expected_value, _default_value, _entry)
    _undefined
  end

  # Compare the timestamp seconds and nanoseconds with the expected timestamp.
  def assert_timestamp_matches(expected_ts, ts_secs, ts_nanos, entry)
    assert_equal expected_ts.tv_sec, ts_secs, entry
    # Fluentd v0.14 onwards supports nanosecond timestamp values.
    # Added in 600 ns delta to avoid flaky tests introduced
    # due to rounding error in double-precision floating-point numbers
    # (to account for the missing 9 bits of precision ~ 512 ns).
    # See http://wikipedia.org/wiki/Double-precision_floating-point_format.
    assert_in_delta expected_ts.tv_nsec, ts_nanos, 600, entry
  end

  def assert_prometheus_metric_value(metric_name, expected_value, labels = {})
    metric = Prometheus::Client.registry.get(metric_name)
    assert_not_nil(metric)
    metric_value = if labels == :aggregate
                     # Sum up all metric values regardless of the labels.
                     metric.values.values.reduce(0.0, :+)
                   else
                     metric.get(labels)
                   end
    assert_equal(expected_value, metric_value)
  end

  def assert_opencensus_metric_value(metric_name, expected_value, labels = {})
    translator = Monitoring::MetricTranslator.new(metric_name, labels)
    metric_name = translator.name
    labels = translator.translate_labels(labels)
    # The next line collapses the labels to assert against the aggregated data,
    # which can have some labels removed. Without this, it would test against
    # the raw data. The view is more representative of the user experience, even
    # though both tests should work because currently we only aggregate away one
    # label that never changes during runtime.
    labels.select! { |k, _| translator.view_labels.include? k }
    labels = labels.map { |k, v| [k.to_s, v.to_s] }.to_h
    stats_recorder = OpenCensus::Stats.ensure_recorder
    view_data = stats_recorder.view_data metric_name
    assert_not_nil(view_data)
    # For now assume all metrics are counters.
    assert_kind_of(OpenCensus::Stats::Aggregation::Sum,
                   view_data.view.aggregation)
    assert_true(view_data.view.measure.int64?)
    tag_values = view_data.view.columns.map { |column| labels[column] }
    metric_value = 0
    if view_data.data.key? tag_values
      metric_value = view_data.data[tag_values].value
    end
    assert_equal(expected_value, metric_value)
  end
end
