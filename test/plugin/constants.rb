# coding: utf-8
# Copyright 2017 Google Inc. All rights reserved.
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

# Add some helper methods to standard classes.
module Google
  module Protobuf
    Any.class_eval do
      # TODO(igorpeshansky): Remove this once
      # https://github.com/google/protobuf/pull/4719 gets released.
      def self.pack(msg, type_url_prefix = 'type.googleapis.com/')
        any = Google::Protobuf::Any.new
        any.pack(msg, type_url_prefix)
        any
      end
    end
  end
end
String.class_eval do
  def inspect_octal
    specials = {
      'a' => '\\007',
      'b' => '\\010',
      'v' => '\\013',
      'f' => '\\014',
      'r' => '\\015'
    }.freeze
    inspect.gsub(/\\([abvfr])/) { specials[Regexp.last_match(1)] } \
           .gsub(/\\x([0-9A-F][0-9A-F])/) do
             format('\\%03o', Regexp.last_match(1).to_i(16))
           end
  end
end

# Constants used by unit tests for Google Cloud Logging plugin.
module Constants
  include Fluent::GoogleCloudOutput::ServiceConstants
  include Fluent::GoogleCloudOutput::ConfigConstants
  include Fluent::GoogleCloudOutput::InternalConstants

  # Generic attributes.
  HOSTNAME = Socket.gethostname
  CUSTOM_LOGGING_API_URL = 'http://localhost:52000'.freeze

  # TODO(qingling128) Separate constants into different submodules.
  # Attributes used for the GCE metadata service.
  PROJECT_ID = 'test-project-id'.freeze
  ZONE = 'us-central1-b'.freeze
  FULLY_QUALIFIED_ZONE = "projects/#{PROJECT_ID}/zones/#{ZONE}".freeze
  VM_ID = '9876543210'.freeze

  RANDOM_LOCAL_RESOURCE_ID = 'ehb.jjk.poq.ll'.freeze

  # Attributes used for the Metadata Agent resources.
  METADATA_ZONE = 'us-central1-c'.freeze
  METADATA_VM_ID = '0123456789'.freeze

  # Attributes used for custom (overridden) configs.
  CUSTOM_PROJECT_ID = 'test-custom-project-id'.freeze
  CUSTOM_ZONE = 'us-custom-central1-b'.freeze
  CUSTOM_FULLY_QUALIFIED_ZONE = "projects/#{PROJECT_ID}/zones/#{ZONE}".freeze
  CUSTOM_VM_ID = 'C9876543210'.freeze
  CUSTOM_HOSTNAME = 'custom.hostname.org'.freeze
  # Kubernetes-specific attributes.
  CUSTOM_K8S_CLUSTER_NAME = 'kubernetes-cluster'.freeze
  CUSTOM_K8S_LOCATION = 'kubernetes-location'.freeze

  # Attributes used for the EC2 metadata service.
  EC2_PROJECT_ID = 'test-ec2-project-id'.freeze
  EC2_ZONE = 'us-west-2b'.freeze
  EC2_PREFIXED_ZONE = "aws:#{EC2_ZONE}".freeze
  EC2_REGION = 'us-west-2'.freeze
  EC2_PREFIXED_REGION = "aws:#{EC2_REGION}".freeze
  EC2_VM_ID = 'i-81c16767'.freeze
  EC2_ACCOUNT_ID = '123456789012'.freeze

  # The formatting here matches the format used on the VM.
  EC2_IDENTITY_DOCUMENT = %({
    "accountId" : "#{EC2_ACCOUNT_ID}",
    "availabilityZone" : "#{EC2_ZONE}",
    "region" : "#{EC2_REGION}",
    "instanceId" : "#{EC2_VM_ID}"
  }).freeze

  # Managed VMs specific labels.
  MANAGED_VM_BACKEND_NAME = 'default'.freeze
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'.freeze

  # LogEntry fields for extraction.
  INSERT_ID = 'fah7yr7iw64tg857y'.freeze
  INSERT_ID2 = 'fah7yr7iw64tgaeuf'.freeze
  SPAN_ID = '000000000000004a'.freeze
  SPAN_ID2 = '000000000000007e'.freeze
  TRACE = 'projects/proj1/traces/1234567890abcdef1234567890abcdef'.freeze
  TRACE2 = 'projects/proj1/traces/1234567890abcdef1234567890fedcba'.freeze
  TRACE_SAMPLED = true
  TRACE_SAMPLED2 = false

  STACKDRIVER_TRACE_ID = '1234567890abcdef1234567890abcdef'.freeze
  FULL_STACKDRIVER_TRACE = \
    "projects/#{PROJECT_ID}/traces/#{STACKDRIVER_TRACE_ID}".freeze

  # Invalid trace id for stackdriver.
  EMPTY_STRING = ''.freeze
  INVALID_SHORT_STACKDRIVER_TRACE_ID = '1234567890abcdef'.freeze
  INVALID_LONG_STACKDRIVER_TRACE_ID = \
    '1234567890abcdef1234567890abcdef123'.freeze
  INVALID_NON_HEX_STACKDRIVER_TRACE_ID = \
    '1234567890abcdef1234567890abcdeZ'.freeze

  # Invalid full format of stackdriver trace.
  INVALID_TRACE_NO_TRACE_ID = "projects/#{PROJECT_ID}/traces/".freeze
  INVALID_TRACE_NO_PROJECT_ID = \
    "projects//traces/#{STACKDRIVER_TRACE_ID}".freeze
  INVALID_TRACE_WITH_SHORT_TRACE_ID = \
    "projects/#{PROJECT_ID}/traces/#{INVALID_SHORT_STACKDRIVER_TRACE_ID}".freeze
  INVALID_TRACE_WITH_LONG_TRACE_ID = \
    "projects/#{PROJECT_ID}/traces/#{INVALID_LONG_STACKDRIVER_TRACE_ID}".freeze
  INVALID_TRACE_WITH_NON_HEX_TRACE_ID = \
    "projects/#{PROJECT_ID}/" \
    "traces/#{INVALID_NON_HEX_STACKDRIVER_TRACE_ID}".freeze

  # New K8s resource constants.
  K8S_LOCATION = 'us-central1-b'.freeze
  K8S_LOCATION2 = 'us-central1-c'.freeze
  K8S_CLUSTER_NAME = 'cluster-1'.freeze
  K8S_NAMESPACE_NAME = 'kube-system'.freeze
  K8S_NODE_NAME = 'performance--default-pool-cabf1342-08jc'.freeze
  K8S_POD_NAME = 'redis-master-c0l82.foo.bar'.freeze
  K8S_CONTAINER_NAME = 'redis'.freeze
  K8S_STREAM = 'stdout'.freeze
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch.
  K8S_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'.freeze
  K8S_SECONDS_EPOCH = 1_234_567_890
  K8S_NANOS = 987_654_321
  K8S_CONTAINER_LOCAL_RESOURCE_ID_PREFIX = 'k8s_container'.freeze
  K8S_POD_LOCAL_RESOURCE_ID_PREFIX = 'k8s_pod'.freeze
  K8S_NODE_LOCAL_RESOURCE_ID_PREFIX = 'k8s_node'.freeze
  K8S_TAG =
    "var.log.containers.#{K8S_NAMESPACE_NAME}_#{K8S_POD_NAME}_" \
    "#{K8S_CONTAINER_NAME}.log".freeze
  K8S_LOCAL_RESOURCE_ID =
    "#{K8S_CONTAINER_LOCAL_RESOURCE_ID_PREFIX}" \
    ".#{K8S_NAMESPACE_NAME}" \
    ".#{K8S_POD_NAME}" \
    ".#{K8S_CONTAINER_NAME}".freeze

  # Container Engine / Kubernetes specific labels.
  CONTAINER_NAMESPACE_ID = '898268c8-4a36-11e5-9d81-42010af0194c'.freeze
  CONTAINER_POD_ID = 'cad3c3c4-4b9c-11e5-9d81-42010af0194c'.freeze
  CONTAINER_LABEL_KEY = 'component'.freeze
  CONTAINER_LABEL_VALUE = 'redis-component'.freeze
  CONTAINER_SEVERITY = 'INFO'.freeze
  CONTAINER_LOCAL_RESOURCE_ID_PREFIX = 'gke_container'.freeze

  # Dataflow specific labels.
  DATAFLOW_REGION = 'us-central1'.freeze
  DATAFLOW_JOB_NAME = 'job_name_1'.freeze
  DATAFLOW_JOB_ID = 'job_id_1'.freeze
  DATAFLOW_STEP_ID = 'step_1'.freeze
  DATAFLOW_TAG = 'dataflow-worker'.freeze

  # Dataproc specific labels.
  DATAPROC_CLUSTER_NAME = 'test-cluster'.freeze
  DATAPROC_CLUSTER_UUID = '00000000-0000-0000-0000-000000000000'.freeze
  DATAPROC_REGION = 'unittest'.freeze

  # ML specific labels.
  ML_REGION = 'us-central1'.freeze
  ML_JOB_ID = 'job_name_1'.freeze
  ML_TASK_NAME = 'task_name_1'.freeze
  ML_TRIAL_ID = 'trial_id_1'.freeze
  ML_LOG_AREA = 'log_area_1'.freeze
  ML_TAG = 'master-replica-0'.freeze

  # Parameters used for authentication.
  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'.freeze
  FAKE_AUTH_TOKEN = 'abc123'.freeze

  # Information about test credentials files.
  # path: Path to the credentials file.
  # project_id: ID of the project, which must correspond to the file contents.
  IAM_CREDENTIALS = {
    path: 'test/plugin/data/iam-credentials.json',
    project_id: 'fluent-test-project'
  }.freeze
  NEW_STYLE_CREDENTIALS = {
    path: 'test/plugin/data/new-style-credentials.json',
    project_id: 'fluent-test-project'
  }.freeze
  LEGACY_CREDENTIALS = {
    path: 'test/plugin/data/credentials.json',
    project_id: '847859579879'
  }.freeze
  INVALID_CREDENTIALS = {
    path: 'test/plugin/data/invalid_credentials.json',
    project_id: ''
  }.freeze

  # Special googleauth environment variables.
  PROJECT_ID_VAR = 'GOOGLE_PROJECT_ID'.freeze
  PRIVATE_KEY_VAR = 'GOOGLE_PRIVATE_KEY'.freeze
  CLIENT_EMAIL_VAR = 'GOOGLE_CLIENT_EMAIL'.freeze
  CLIENT_ID_VAR = 'GOOGLE_CLIENT_ID'.freeze
  CLIENT_SECRET_VAR = 'GOOGLE_CLIENT_SECRET'.freeze
  REFRESH_TOKEN_VAR = 'GOOGLE_REFRESH_TOKEN'.freeze

  # Configuration files for various test scenarios.
  APPLICATION_DEFAULT_CONFIG = %(
  ).freeze

  CUSTOM_LOGGING_API_URL_CONFIG = %(
    logging_api_url #{CUSTOM_LOGGING_API_URL}
  ).freeze

  DETECT_JSON_CONFIG = %(
    detect_json true
  ).freeze

  # rubocop:disable Metrics/LineLength
  PRIVATE_KEY_CONFIG = %(
     auth_method private_key
     private_key_email 271661262351-ft99kc9kjro9rrihq3k2n3s2inbplu0q@developer.gserviceaccount.com
     private_key_path test/plugin/data/c31e573fd7f62ed495c9ca3821a5a85cb036dee1-privatekey.p12
  ).freeze
  # rubocop:enable Metrics/LineLength

  REQUIRE_VALID_TAGS_CONFIG = %(
    require_valid_tags true
  ).freeze

  NO_METADATA_SERVICE_CONFIG = %(
    use_metadata_service false
  ).freeze

  NO_DETECT_SUBSERVICE_CONFIG = %(
    detect_subservice false
  ).freeze

  ENABLE_SPLIT_LOGS_BY_TAG_CONFIG = %(
    split_logs_by_tag true
  ).freeze

  ENABLE_PROMETHEUS_CONFIG = %(
    enable_monitoring true
    monitoring_type prometheus
  ).freeze

  ENABLE_OPENCENSUS_CONFIG = %(
    enable_monitoring true
    monitoring_type opencensus
  ).freeze

  ENABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG = %(
    autoformat_stackdriver_trace true
  ).freeze

  DISABLE_AUTOFORMAT_STACKDRIVER_TRACE_CONFIG = %(
    autoformat_stackdriver_trace false
  ).freeze

  CUSTOM_METADATA_CONFIG = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
    vm_name #{CUSTOM_HOSTNAME}
  ).freeze

  CONFIG_MISSING_METADATA_PROJECT_ID = %(
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
  ).freeze
  CONFIG_MISSING_METADATA_ZONE = %(
    project_id #{CUSTOM_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  ).freeze
  CONFIG_MISSING_METADATA_VM_ID = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
  ).freeze
  CONFIG_MISSING_METADATA_ALL = %(
  ).freeze

  CUSTOM_K8S_CONFIG = %(
    k8s_cluster_name #{CUSTOM_K8S_CLUSTER_NAME}
    k8s_cluster_location #{CUSTOM_K8S_LOCATION}
  ).freeze

  EMPTY_K8S_CONFIG = %(
    k8s_cluster_name ""
    k8s_cluster_location ""
  ).freeze

  CONFIG_EC2_PROJECT_ID = %(
    project_id #{EC2_PROJECT_ID}
  ).freeze

  CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID = %(
    project_id #{EC2_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  ).freeze

  CONFIG_EC2_PROJECT_ID_USE_REGION = %(
    project_id #{EC2_PROJECT_ID}
    use_aws_availability_zone false
  ).freeze

  CONFIG_DATAFLOW = %(
    subservice_name "#{DATAFLOW_CONSTANTS[:service]}"
    labels {
      "#{DATAFLOW_CONSTANTS[:service]}/region" : "#{DATAFLOW_REGION}",
      "#{DATAFLOW_CONSTANTS[:service]}/job_name" : "#{DATAFLOW_JOB_NAME}",
      "#{DATAFLOW_CONSTANTS[:service]}/job_id" : "#{DATAFLOW_JOB_ID}"
    }
    label_map { "step": "#{DATAFLOW_CONSTANTS[:service]}/step_id" }
  ).freeze

  CONFIG_ML = %(
    subservice_name "#{ML_CONSTANTS[:service]}"
    labels {
      "#{ML_CONSTANTS[:service]}/job_id" : "#{ML_JOB_ID}",
      "#{ML_CONSTANTS[:service]}/task_name" : "#{ML_TASK_NAME}",
      "#{ML_CONSTANTS[:service]}/trial_id" : "#{ML_TRIAL_ID}"
    }
    label_map { "name": "#{ML_CONSTANTS[:service]}/job_id/log_area" }
  ).freeze

  CONFIG_CUSTOM_INSERT_ID_KEY_SPECIFIED = %(
    insert_id_key custom_insert_id_key
  ).freeze

  CONFIG_CUSTOM_LABELS_KEY_SPECIFIED = %(
    labels_key custom_labels_key
  ).freeze

  CONFIG_CUSTOM_OPERATION_KEY_SPECIFIED = %(
    operation_key custom_operation_key
  ).freeze

  CONFIG_CUSTOM_SOURCE_LOCATION_KEY_SPECIFIED = %(
    source_location_key custom_source_location_key
  ).freeze

  CONFIG_CUSTOM_SPAN_ID_KEY_SPECIFIED = %(
    span_id_key custom_span_id_key
  ).freeze

  CONFIG_CUSTOM_TRACE_KEY_SPECIFIED = %(
    trace_key custom_trace_key
  ).freeze

  CONFIG_CUSTOM_TRACE_SAMPLED_KEY_SPECIFIED = %(
    trace_sampled_key custom_trace_sampled_key
  ).freeze

  # For 'labels' config.
  LABELS_FROM_LABELS_CONFIG = {
    'a_label_from_labels_config' => 'some_value',
    'another_label_from_labels_config' => 'some_value'
  }.freeze
  CONFIG_LABELS = %(
    labels #{LABELS_FROM_LABELS_CONFIG.to_json}
  ).freeze

  # For 'label_map' config.
  LABEL_MAP_HASH = {
    'target_field_from_payload' => 'a_label_from_label_map_config',
    'another_target_field_from_payload' => 'another_label_from_label_map_config'
  }.freeze
  PAYLOAD_FOR_LABEL_MAP = {
    'target_field_from_payload' => 'a_value',
    'another_target_field_from_payload' => 'b_value'
  }.freeze
  LABELS_FROM_LABEL_MAP_CONFIG = {
    'a_label_from_label_map_config' => 'a_value',
    'another_label_from_label_map_config' => 'b_value'
  }.freeze
  CONFIG_LABEL_MAP = %(
    label_map #{LABEL_MAP_HASH.to_json}
  ).freeze

  CONFIG_LABLES_AND_LABLE_MAP = %(
    #{CONFIG_LABELS}
    #{CONFIG_LABEL_MAP}
  ).freeze

  # For conflicting labels.
  CONFLICTING_LABEL_NAME = 'conflicting_label_key'.freeze
  CONFLICTING_LABEL_VALUE1 = 'conflicting_value_1'.freeze
  CONFLICTING_LABEL_VALUE2 = 'conflicting_value_2'.freeze
  CONFLICTING_LABEL_VALUE3 = 'conflicting_value_3'.freeze
  LABELS_FROM_PAYLOAD_CONFLICTING = {
    CONFLICTING_LABEL_NAME => CONFLICTING_LABEL_VALUE1
  }.freeze
  LABELS_FROM_LABEL_MAP_CONFIG_CONFLICTING = {
    CONFLICTING_LABEL_NAME => CONFLICTING_LABEL_VALUE2
  }.freeze
  LABELS_FROM_LABELS_CONFIG_CONFLICTING = {
    CONFLICTING_LABEL_NAME => CONFLICTING_LABEL_VALUE3
  }.freeze

  LABEL_MAP_HASH_CONFLICTING = {
    'target_field_from_payload' => CONFLICTING_LABEL_NAME
  }.freeze
  PAYLOAD_FOR_LABEL_MAP_CONFLICTING = {
    'target_field_from_payload' => CONFLICTING_LABEL_VALUE2
  }.freeze
  CONFIG_LABEL_MAP_CONFLICTING = %(
    label_map #{LABEL_MAP_HASH_CONFLICTING.to_json}
  ).freeze
  CONFIG_LABELS_CONFLICTING = %(
    labels #{LABELS_FROM_LABELS_CONFIG_CONFLICTING.to_json}
  ).freeze
  CONFIG_LABLES_AND_LABLE_MAP_CONFLICTING = %(
    #{CONFIG_LABELS_CONFLICTING}
    #{CONFIG_LABEL_MAP_CONFLICTING}
  ).freeze

  # For monitoring config.
  CONFIG_UNKNOWN_MONITORING_TYPE = %(
    enable_monitoring  true
    monitoring_type    not_prometheus
  ).freeze

  # For statusz.
  CONFIG_STATUSZ = %(
    statusz_port                  5678

    adjust_invalid_timestamps     false
    autoformat_stackdriver_trace  false
    coerce_to_utf8                false
    detect_json                   true
    detect_subservice             false
    enable_monitoring             true
    http_request_key              test_http_request_key
    insert_id_key                 test_insert_id_key
    k8s_cluster_location          test-k8s-cluster-location
    k8s_cluster_name              test-k8s-cluster-name
    kubernetes_tag_regexp         .*test-regexp.*
    label_map                     { "label_map_key": "label_map_value" }
    labels_key                    test_labels_key
    labels                        { "labels_key": "labels_value" }
    logging_api_url               http://localhost:52000
    monitoring_type               not_prometheus
    non_utf8_replacement_string   zzz
    operation_key                 test_operation_key
    project_id                    test-project-id-123
    require_valid_tags            true
    source_location_key           test_source_location_key
    span_id_key                   test_span_id_key
    split_logs_by_tag             true
    subservice_name               test_subservice_name
    trace_key                     test_trace_key
    trace_sampled_key             test_trace_sampled_key
    use_aws_availability_zone     false
    use_grpc                      true
    use_metadata_service          false
    vm_id                         12345
    vm_name                       test.hostname.org
    zone                          asia-east2
  ).freeze

  # Service configurations for various services.

  # GCE.
  COMPUTE_PARAMS_NO_LOG_NAME = {
    resource: {
      type: COMPUTE_CONSTANTS[:resource_type],
      labels: {
        'instance_id' => VM_ID,
        'zone' => ZONE
      }
    },
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }.freeze
  COMPUTE_PARAMS = COMPUTE_PARAMS_NO_LOG_NAME.merge(
    log_name: 'test'
  ).freeze
  COMPUTE_PARAMS_WITH_METADATA_VM_ID_AND_ZONE = COMPUTE_PARAMS.merge(
    resource: COMPUTE_PARAMS[:resource].merge(
      labels: {
        'instance_id' => METADATA_VM_ID,
        'zone' => METADATA_ZONE
      }
    )
  ).freeze

  # GAE.
  VMENGINE_PARAMS = {
    resource: {
      type: APPENGINE_CONSTANTS[:resource_type],
      labels: {
        'module_id' => MANAGED_VM_BACKEND_NAME,
        'version_id' => MANAGED_VM_BACKEND_VERSION
      }
    },
    log_name: "#{APPENGINE_CONSTANTS[:service]}%2Ftest",
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }.freeze

  # GKE Container.
  CONTAINER_TAG =
    "kubernetes.#{K8S_POD_NAME}_#{K8S_NAMESPACE_NAME}_" \
    "#{K8S_CONTAINER_NAME}".freeze

  CONTAINER_FROM_METADATA_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => K8S_CLUSTER_NAME,
        'namespace_id' => CONTAINER_NAMESPACE_ID,
        'instance_id' => VM_ID,
        'pod_id' => CONTAINER_POD_ID,
        'container_name' => K8S_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: K8S_CONTAINER_NAME,
    project_id: PROJECT_ID,
    labels: {
      "#{GKE_CONSTANTS[:service]}/namespace_name" => K8S_NAMESPACE_NAME,
      "#{GKE_CONSTANTS[:service]}/pod_name" => K8S_POD_NAME,
      "#{GKE_CONSTANTS[:service]}/stream" => K8S_STREAM,
      "label/#{CONTAINER_LABEL_KEY}" => CONTAINER_LABEL_VALUE,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }.freeze

  # Almost the same as from metadata, but namespace_id and pod_id come from
  # namespace and pod names.
  CONTAINER_FROM_TAG_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => K8S_CLUSTER_NAME,
        'namespace_id' => K8S_NAMESPACE_NAME,
        'instance_id' => VM_ID,
        'pod_id' => K8S_POD_NAME,
        'container_name' => K8S_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: K8S_CONTAINER_NAME,
    project_id: PROJECT_ID,
    labels: {
      "#{GKE_CONSTANTS[:service]}/namespace_name" => K8S_NAMESPACE_NAME,
      "#{GKE_CONSTANTS[:service]}/pod_name" => K8S_POD_NAME,
      "#{GKE_CONSTANTS[:service]}/stream" => K8S_STREAM,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }.freeze

  CONTAINER_FROM_APPLICATION_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => K8S_CLUSTER_NAME,
        'namespace_id' => CONTAINER_NAMESPACE_ID,
        'instance_id' => VM_ID,
        'pod_id' => CONTAINER_POD_ID,
        'container_name' => K8S_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: 'redis',
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }.freeze

  # K8s Container.
  K8S_CONTAINER_PARAMS = {
    resource: {
      type: K8S_CONTAINER_CONSTANTS[:resource_type],
      labels: {
        'namespace_name' => K8S_NAMESPACE_NAME,
        'pod_name' => K8S_POD_NAME,
        'container_name' => K8S_CONTAINER_NAME,
        'cluster_name' => K8S_CLUSTER_NAME,
        'location' => K8S_LOCATION
      }
    },
    project_id: PROJECT_ID,
    labels: {}
  }.freeze
  K8S_CONTAINER_PARAMS_FROM_LOCAL = K8S_CONTAINER_PARAMS.merge(
    resource: K8S_CONTAINER_PARAMS[:resource].merge(
      labels: K8S_CONTAINER_PARAMS[:resource][:labels].merge(
        'location' => K8S_LOCATION2
      )
    )
  ).freeze
  K8S_CONTAINER_PARAMS_CUSTOM = K8S_CONTAINER_PARAMS.merge(
    resource: K8S_CONTAINER_PARAMS[:resource].merge(
      labels: K8S_CONTAINER_PARAMS[:resource][:labels].merge(
        'cluster_name' => CUSTOM_K8S_CLUSTER_NAME,
        'location' => CUSTOM_K8S_LOCATION
      )
    )
  ).freeze
  # Used in k8s fallback tests.
  K8S_CONTAINER_PARAMS_FROM_FALLBACK = COMPUTE_PARAMS_NO_LOG_NAME.merge(
    log_name: CONTAINER_TAG
  ).freeze

  # K8s Pod.
  K8S_POD_PARAMS = {
    resource: {
      type: K8S_POD_CONSTANTS[:resource_type],
      labels: {
        'namespace_name' => K8S_NAMESPACE_NAME,
        'pod_name' => K8S_POD_NAME,
        'cluster_name' => K8S_CLUSTER_NAME,
        'location' => K8S_LOCATION
      }
    },
    project_id: PROJECT_ID,
    labels: {}
  }.freeze
  K8S_POD_PARAMS_FROM_LOCAL = K8S_POD_PARAMS.merge(
    resource: K8S_POD_PARAMS[:resource].merge(
      labels: K8S_POD_PARAMS[:resource][:labels].merge(
        'location' => K8S_LOCATION2
      )
    )
  ).freeze
  K8S_POD_PARAMS_CUSTOM = K8S_POD_PARAMS.merge(
    resource: K8S_POD_PARAMS[:resource].merge(
      labels: K8S_POD_PARAMS[:resource][:labels].merge(
        'cluster_name' => CUSTOM_K8S_CLUSTER_NAME,
        'location' => CUSTOM_K8S_LOCATION
      )
    )
  ).freeze

  # K8s Node.
  K8S_NODE_PARAMS = {
    resource: {
      type: K8S_NODE_CONSTANTS[:resource_type],
      labels: {
        'node_name' => K8S_NODE_NAME,
        'cluster_name' => K8S_CLUSTER_NAME,
        'location' => K8S_LOCATION
      }
    },
    log_name: 'test',
    project_id: PROJECT_ID,
    labels: {}
  }.freeze
  K8S_NODE_PARAMS_FROM_LOCAL = K8S_NODE_PARAMS.merge(
    resource: K8S_NODE_PARAMS[:resource].merge(
      labels: K8S_NODE_PARAMS[:resource][:labels].merge(
        'location' => K8S_LOCATION2
      )
    )
  ).freeze
  K8S_NODE_PARAMS_CUSTOM = K8S_NODE_PARAMS.merge(
    resource: K8S_NODE_PARAMS[:resource].merge(
      labels: K8S_NODE_PARAMS[:resource][:labels].merge(
        'cluster_name' => CUSTOM_K8S_CLUSTER_NAME,
        'location' => CUSTOM_K8S_LOCATION
      )
    )
  ).freeze

  # Cloud Dataflow.
  DATAFLOW_PARAMS = {
    resource: {
      type: DATAFLOW_CONSTANTS[:resource_type],
      labels: {
        'job_name' => DATAFLOW_JOB_NAME,
        'job_id' => DATAFLOW_JOB_ID,
        'step_id' => DATAFLOW_STEP_ID,
        'region' => DATAFLOW_REGION
      }
    },
    log_name: DATAFLOW_TAG,
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }.freeze

  # Cloud Dataproc.
  DATAPROC_PARAMS = {
    resource: {
      type: DATAPROC_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => DATAPROC_CLUSTER_NAME,
        'cluster_uuid' => DATAPROC_CLUSTER_UUID,
        'region' => DATAPROC_REGION
      }
    },
    log_name: 'test',
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }.freeze

  # Cloud ML.
  ML_PARAMS = {
    resource: {
      type: ML_CONSTANTS[:resource_type],
      labels: {
        'job_id' => ML_JOB_ID,
        'task_name' => ML_TASK_NAME
      }
    },
    log_name: ML_TAG,
    project_id: PROJECT_ID,
    labels: {
      "#{ML_CONSTANTS[:service]}/trial_id" => ML_TRIAL_ID,
      "#{ML_CONSTANTS[:service]}/job_id/log_area" => ML_LOG_AREA,
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }.freeze

  CUSTOM_PARAMS = {
    resource: {
      type: COMPUTE_CONSTANTS[:resource_type],
      labels: {
        'instance_id' => CUSTOM_VM_ID,
        'zone' => CUSTOM_ZONE
      }
    },
    log_name: 'test',
    project_id: CUSTOM_PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => CUSTOM_HOSTNAME
    }
  }.freeze

  EC2_REGION_PARAMS = {
    resource: {
      type: EC2_CONSTANTS[:resource_type],
      labels: {
        'instance_id' => EC2_VM_ID,
        'region' => EC2_PREFIXED_REGION,
        'aws_account' => EC2_ACCOUNT_ID
      }
    },
    log_name: 'test',
    project_id: EC2_PROJECT_ID,
    labels: {
      "#{EC2_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }.freeze

  EC2_ZONE_PARAMS = EC2_REGION_PARAMS.merge(
    resource: EC2_REGION_PARAMS[:resource].merge(
      labels: EC2_REGION_PARAMS[:resource][:labels].merge(
        'region' => EC2_PREFIXED_ZONE
      )
    )
  ).freeze

  HTTP_REQUEST_MESSAGE = {
    'cacheFillBytes' => '6653',
    'cacheHit' => true,
    'cacheLookup' => true,
    'cacheValidatedWithOriginServer' => true,
    'protocol' => 'HTTP/1.1',
    'referer' => 'http://referer/',
    'remoteIp' => '55.55.55.55',
    'responseSize' => '65',
    'requestMethod' => 'POST',
    'requestSize' => '210',
    'requestUrl' => 'http://example/',
    'serverIp' => '66.66.66.66',
    'status' => 200,
    'userAgent' => 'USER AGENT 1.0'
  }.freeze

  SOURCE_LOCATION_MESSAGE = {
    'file' => 'source/file',
    'function' => 'my_function',
    'line' => '18'
  }.freeze

  SOURCE_LOCATION_MESSAGE2 = {
    'file' => 'src/file',
    'function' => 'my_func',
    'line' => '8'
  }.freeze

  OPERATION_MESSAGE = {
    'id' => 'op_id',
    'producer' => 'my/app',
    'last' => true
  }.freeze

  OPERATION_MESSAGE2 = {
    'id' => 'op_id2',
    'producer' => 'my/app2',
    'last' => false
  }.freeze

  LABELS_MESSAGE = {
    'component' => 'front-end',
    'source' => 'user',
    'app' => 'request-router'
  }.freeze

  LABELS_MESSAGE2 = {
    'component' => 'front-end',
    'source' => 'system',
    'app' => 'request-router'
  }.freeze

  CUSTOM_LABELS_MESSAGE = {
    'customKey' => 'value'
  }.freeze
  CONFLICTING_LABEL_KEY = "#{COMPUTE_CONSTANTS[:service]}/resource_name".freeze

  # Tags and their sanitized and encoded version.
  VALID_TAGS = {
    'test' => 'test',
    'germanß' => 'german%C3%9F',
    'chinese中' => 'chinese%E4%B8%AD',
    'specialCharacter/_-.' => 'specialCharacter%2F_-.',
    'abc@&^$*' => 'abc%40%26%5E%24%2A',
    '@&^$*' => '%40%26%5E%24%2A'
  }.freeze
  INVALID_TAGS = {
    # Non-string tags.
    123 => '123',
    1.23 => '1.23',
    [1, 2, 3] => '%5B1%2C%202%2C%203%5D',
    { key: 'value' } => '%7B%22key%22%3D%3E%22value%22%7D',
    # Non-utf8 string tags.
    "nonutf8#{[0x92].pack('C*')}" => 'nonutf8%20',
    "abc#{[0x92].pack('C*')}" => 'abc%20',
    [0x92].pack('C*') => '%20',
    # Empty string tag.
    '' => '_'
  }.freeze
  ALL_TAGS = VALID_TAGS.merge(INVALID_TAGS)

  # Stub value for Monitored resources from Metadata Agent.
  # Map from the local_resource_id to the retrieved monitored resource.
  MONITORED_RESOURCE_STUBS = {
    # GKE container logs.
    "#{CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{CONTAINER_NAMESPACE_ID}" \
    ".#{K8S_POD_NAME}.#{K8S_CONTAINER_NAME}" =>
      {
        'type' => GKE_CONSTANTS[:resource_type],
        'labels' => {
          'cluster_name' => K8S_CLUSTER_NAME,
          'container_name' => K8S_CONTAINER_NAME,
          'instance_id' => VM_ID,
          'namespace_id' => CONTAINER_NAMESPACE_ID,
          'pod_id' => CONTAINER_POD_ID,
          'zone' => ZONE
        }
      }.to_json,
    # K8s container logs.
    "#{K8S_CONTAINER_LOCAL_RESOURCE_ID_PREFIX}.#{K8S_NAMESPACE_NAME}" \
    ".#{K8S_POD_NAME}.#{K8S_CONTAINER_NAME}" =>
      {
        'type' => K8S_CONTAINER_CONSTANTS[:resource_type],
        'labels' => {
          'namespace_name' => K8S_NAMESPACE_NAME,
          'pod_name' => K8S_POD_NAME,
          'container_name' => K8S_CONTAINER_NAME,
          'cluster_name' => K8S_CLUSTER_NAME,
          'location' => K8S_LOCATION
        }
      }.to_json,
    # K8s pod logs.
    "#{K8S_POD_LOCAL_RESOURCE_ID_PREFIX}.#{K8S_NAMESPACE_NAME}" \
    ".#{K8S_POD_NAME}" =>
      {
        'type' => K8S_POD_CONSTANTS[:resource_type],
        'labels' => {
          'namespace_name' => K8S_NAMESPACE_NAME,
          'pod_name' => K8S_POD_NAME,
          'cluster_name' => K8S_CLUSTER_NAME,
          'location' => K8S_LOCATION
        }
      }.to_json,
    # K8s node logs.
    "#{K8S_NODE_LOCAL_RESOURCE_ID_PREFIX}.#{K8S_NODE_NAME}" =>
      {
        'type' => K8S_NODE_CONSTANTS[:resource_type],
        'labels' => {
          'node_name' => K8S_NODE_NAME,
          'cluster_name' => K8S_CLUSTER_NAME,
          'location' => K8S_LOCATION
        }
      }.to_json
  }.freeze

  PARTIAL_SUCCESS_RESPONSE_BODY = {
    'error' => {
      'code' => 403,
      'message' => 'User not authorized.',
      'status' => 'PERMISSION_DENIED',
      'details' => [
        {
          '@type' => 'type.googleapis.com/google.logging.v2.WriteLogEntriesPa' \
            'rtialErrors',
          'logEntryErrors' => {
            '0' => {
              'code' => 7,
              'message' => 'User not authorized.'
            },
            '1' => {
              'code' => 3,
              'message' => 'Log name contains illegal character :'
            },
            '2' => {
              'code' => 3,
              'message' => 'Log name contains illegal character :'
            }
          }
        },
        {
          '@type' => 'type.googleapis.com/google.rpc.DebugInfo',
          'detail' => '[ORIGINAL ERROR] generic::permission_denied: User not ' \
            'authorized. [google.rpc.error_details_ext] { message: \"User not' \
            ' authorized.\" details { type_url: \"type.googleapis.com/google.' \
            'logging.v2.WriteLogEntriesPartialErrors\" value: \"\\n\\034\\010' \
            '\\000\\022\\030\\010\\007\\022\\024User not authorized.\\n-\\010' \
            '\\001\\022)\\010\\003\\022%Log name contains illegal character :' \
            '\\n-\\010\\002\\022)\\010\\003\\022%Log name contains illegal ch' \
            'aracter :\" } }'
        }
      ]
    }
  }.freeze

  PARTIAL_SUCCESS_GRPC_METADATA = begin
    partial_errors = Google::Logging::V2::WriteLogEntriesPartialErrors.new(
      log_entry_errors: {
        0 => Google::Rpc::Status.new(
          code: GRPC::Core::StatusCodes::PERMISSION_DENIED,
          message: 'User not authorized.',
          details: []),
        1 => Google::Rpc::Status.new(
          code: GRPC::Core::StatusCodes::INVALID_ARGUMENT,
          message: 'Log name contains illegal character :',
          details: []),
        3 => Google::Rpc::Status.new(
          code: GRPC::Core::StatusCodes::INVALID_ARGUMENT,
          message: 'Log name contains illegal character :',
          details: [])
      })
    status = Google::Rpc::Status.new(
      message: 'User not authorized.',
      details: [Google::Protobuf::Any.pack(partial_errors)])
    debug_info = Google::Rpc::DebugInfo.new(
      detail: '[ORIGINAL ERROR] generic::permission_denied: User not' \
        ' authorized. [google.rpc.error_details_ext] { message:' \
        " #{status.message.inspect} details { type_url:" \
        " #{status.details[0].type_url.inspect} value:" \
        " #{status.details[0].value.inspect_octal} } }")
    status_details = Google::Rpc::Status.new(
      code: 7, message: 'User not authorized.',
      details: [Google::Protobuf::Any.pack(partial_errors),
                Google::Protobuf::Any.pack(debug_info)])
    {
      'google.logging.v2.writelogentriespartialerrors-bin' =>
        partial_errors.to_proto,
      'google.rpc.debuginfo-bin' => debug_info.to_proto,
      'grpc-status-details-bin' => status_details.to_proto
    }.freeze
  end

  PARSE_ERROR_RESPONSE_BODY = {
    'error' => {
      'code' => 400,
      'message' => 'Request contains an invalid argument.',
      'status' => 'INVALID_ARGUMENT',
      'details' => [
        {
          '@type' => 'type.googleapis.com/google.rpc.DebugInfo',
          'detail' =>
            '[ORIGINAL ERROR] RPC::CLIENT_ERROR: server could not parse' \
              " request sent by client; initialization error is: ''"
        }
      ]
    }
  }.freeze

  PARSE_ERROR_GRPC_METADATA = begin
    debug_info = Google::Rpc::DebugInfo.new(
      detail: '[ORIGINAL ERROR] RPC::CLIENT_ERROR: server could not parse' \
        " request sent by client; initialization error is: ''")
    status_details = Google::Rpc::Status.new(
      code: 3, message: 'internal client error',
      details: [Google::Protobuf::Any.pack(debug_info)])
    {
      'google.rpc.debuginfo-bin' => debug_info.to_proto,
      'grpc-status-details-bin' => status_details.to_proto
    }.freeze
  end

  PRESERVED_KEYS_TIMESTAMP_FIELDS = [
    {
      'time' => K8S_TIMESTAMP
    },
    {
      'timeNanos' => K8S_NANOS
    },
    {
      'timestamp' => {
        'nanos' => K8S_NANOS,
        'seconds' => K8S_SECONDS_EPOCH
      }
    },
    {
      'timestampNanos' => K8S_NANOS,
      'timestampSeconds' => K8S_SECONDS_EPOCH
    }
  ].freeze

  PRESERVED_KEYS_MAP = {
    'severity' => CONTAINER_SEVERITY,
    DEFAULT_HTTP_REQUEST_KEY => HTTP_REQUEST_MESSAGE,
    DEFAULT_INSERT_ID_KEY => INSERT_ID,
    DEFAULT_LABELS_KEY => LABELS_MESSAGE,
    DEFAULT_OPERATION_KEY => OPERATION_MESSAGE,
    DEFAULT_SOURCE_LOCATION_KEY => SOURCE_LOCATION_MESSAGE,
    DEFAULT_SPAN_ID_KEY => SPAN_ID,
    DEFAULT_TRACE_KEY => TRACE,
    DEFAULT_TRACE_SAMPLED_KEY => TRACE_SAMPLED
  }.freeze
end
