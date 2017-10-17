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

# Constants used by unit tests for Google Cloud Logging plugin.
module Constants
  include Fluent::GoogleCloudOutput::ServiceConstants
  include Fluent::GoogleCloudOutput::ConfigConstants
  include Fluent::GoogleCloudOutput::InternalConstants

  # Generic attributes.
  HOSTNAME = Socket.gethostname

  # TODO(qingling128) Separate constants into different submodules.
  # Attributes used for the GCE metadata service.
  PROJECT_ID = 'test-project-id'
  ZONE = 'us-central1-b'
  FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  VM_ID = '9876543210'

  # Attributes used for the Metadata Agent resources.
  METADATA_ZONE = 'us-central1-c'
  METADATA_VM_ID = '0123456789'

  # Attributes used for custom (overridden) configs.
  CUSTOM_PROJECT_ID = 'test-custom-project-id'
  CUSTOM_ZONE = 'us-custom-central1-b'
  CUSTOM_FULLY_QUALIFIED_ZONE = 'projects/' + PROJECT_ID + '/zones/' + ZONE
  CUSTOM_VM_ID = 'C9876543210'
  CUSTOM_HOSTNAME = 'custom.hostname.org'

  # Attributes used for the EC2 metadata service.
  EC2_PROJECT_ID = 'test-ec2-project-id'
  EC2_ZONE = 'us-west-2b'
  EC2_PREFIXED_ZONE = 'aws:' + EC2_ZONE
  EC2_VM_ID = 'i-81c16767'
  EC2_ACCOUNT_ID = '123456789012'

  # The formatting here matches the format used on the VM.
  EC2_IDENTITY_DOCUMENT = %({
    "accountId" : "#{EC2_ACCOUNT_ID}",
    "availabilityZone" : "#{EC2_ZONE}",
    "instanceId" : "#{EC2_VM_ID}"
  })

  # Managed VMs specific labels.
  MANAGED_VM_BACKEND_NAME = 'default'
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'

  # Docker Container labels.
  DOCKER_CONTAINER_ID = '0d0f03ff8d3c42688692536d1af77a28cd135c0a5c531f25a31'
  DOCKER_CONTAINER_NAME = 'happy_hippo'
  DOCKER_CONTAINER_STREAM_STDOUT = 'stdout'
  DOCKER_CONTAINER_STREAM_STDERR = 'stderr'
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch.
  DOCKER_CONTAINER_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'
  DOCKER_CONTAINER_SECONDS_EPOCH = 1_234_567_890
  DOCKER_CONTAINER_NANOS = 987_654_321

  # Container Engine / Kubernetes specific labels.
  CONTAINER_CLUSTER_NAME = 'cluster-1'
  CONTAINER_NAMESPACE_ID = '898268c8-4a36-11e5-9d81-42010af0194c'
  CONTAINER_NAMESPACE_NAME = 'kube-system'
  CONTAINER_POD_ID = 'cad3c3c4-4b9c-11e5-9d81-42010af0194c'
  CONTAINER_POD_NAME = 'redis-master-c0l82.foo.bar'
  CONTAINER_CONTAINER_NAME = 'redis'
  CONTAINER_LABEL_KEY = 'component'
  CONTAINER_LABEL_VALUE = 'redis-component'
  CONTAINER_STREAM = 'stdout'
  CONTAINER_SEVERITY = 'INFO'
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch.
  CONTAINER_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'
  CONTAINER_SECONDS_EPOCH = 1_234_567_890
  CONTAINER_NANOS = 987_654_321

  # Cloud Functions specific labels.
  CLOUDFUNCTIONS_FUNCTION_NAME = '$My_Function.Name-@1'
  CLOUDFUNCTIONS_REGION = 'us-central1'
  CLOUDFUNCTIONS_EXECUTION_ID = '123-0'
  CLOUDFUNCTIONS_CLUSTER_NAME = 'cluster-1'
  CLOUDFUNCTIONS_NAMESPACE_NAME = 'default'
  CLOUDFUNCTIONS_POD_NAME = 'd.dc.myu.uc.functionp.pc.name-a.a1.987-c0l82'
  CLOUDFUNCTIONS_CONTAINER_NAME = 'worker'

  # Dataflow specific labels.
  DATAFLOW_REGION = 'us-central1'
  DATAFLOW_JOB_NAME = 'job_name_1'
  DATAFLOW_JOB_ID = 'job_id_1'
  DATAFLOW_STEP_ID = 'step_1'
  DATAFLOW_TAG = 'dataflow-worker'

  # Dataproc specific labels.
  DATAPROC_CLUSTER_NAME = 'test-cluster'
  DATAPROC_CLUSTER_UUID = '00000000-0000-0000-0000-000000000000'
  DATAPROC_REGION = 'unittest'

  # ML specific labels.
  ML_REGION = 'us-central1'
  ML_JOB_ID = 'job_name_1'
  ML_TASK_NAME = 'task_name_1'
  ML_TRIAL_ID = 'trial_id_1'
  ML_LOG_AREA = 'log_area_1'
  ML_TAG = 'master-replica-0'

  # Parameters used for authentication.
  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
  FAKE_AUTH_TOKEN = 'abc123'

  # Information about test credentials files.
  # path: Path to the credentials file.
  # project_id: ID of the project, which must correspond to the file contents.
  IAM_CREDENTIALS = {
    path: 'test/plugin/data/iam-credentials.json',
    project_id: 'fluent-test-project'
  }
  LEGACY_CREDENTIALS = {
    path: 'test/plugin/data/credentials.json',
    project_id: '847859579879'
  }
  INVALID_CREDENTIALS = {
    path: 'test/plugin/data/invalid_credentials.json',
    project_id: ''
  }

  # Configuration files for various test scenarios.
  APPLICATION_DEFAULT_CONFIG = %(
  )

  DETECT_JSON_CONFIG = %(
    detect_json true
  )

  PARTIAL_SUCCESS_CONFIG = %(
    partial_success true
  )

  # rubocop:disable Metrics/LineLength
  PRIVATE_KEY_CONFIG = %(
     auth_method private_key
     private_key_email 271661262351-ft99kc9kjro9rrihq3k2n3s2inbplu0q@developer.gserviceaccount.com
     private_key_path test/plugin/data/c31e573fd7f62ed495c9ca3821a5a85cb036dee1-privatekey.p12
  )
  # rubocop:enable Metrics/LineLength

  REQUIRE_VALID_TAGS_CONFIG = %(
    require_valid_tags true
  )

  NO_METADATA_SERVICE_CONFIG = %(
    use_metadata_service false
  )

  NO_DETECT_SUBSERVICE_CONFIG = %(
    detect_subservice false
  )

  PROMETHEUS_ENABLE_CONFIG = %(
    enable_monitoring true
    monitoring_type prometheus
  )

  ENABLE_METADATA_AGENT_CONFIG = %(
    enable_metadata_agent true
  )

  DISABLE_METADATA_AGENT_CONFIG = %(
    enable_metadata_agent false
  )

  DOCKER_CONTAINER_CONFIG = %(
    enable_metadata_agent true
    label_map { "source": "#{DOCKER_CONSTANTS[:service]}/stream" }
    detect_json true
  )

  CUSTOM_METADATA_CONFIG = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
    vm_name #{CUSTOM_HOSTNAME}
  )

  CONFIG_MISSING_METADATA_PROJECT_ID = %(
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
  )
  CONFIG_MISSING_METADATA_ZONE = %(
    project_id #{CUSTOM_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  )
  CONFIG_MISSING_METADATA_VM_ID = %(
    project_id #{CUSTOM_PROJECT_ID}
    zone #{CUSTOM_ZONE}
  )
  CONFIG_MISSING_METADATA_ALL = %(
  )

  CONFIG_EC2_PROJECT_ID = %(
    project_id #{EC2_PROJECT_ID}
  )

  CONFIG_EC2_PROJECT_ID_AND_CUSTOM_VM_ID = %(
    project_id #{EC2_PROJECT_ID}
    vm_id #{CUSTOM_VM_ID}
  )

  CONFIG_DATAFLOW = %(
    subservice_name "#{DATAFLOW_CONSTANTS[:service]}"
    labels {
      "#{DATAFLOW_CONSTANTS[:service]}/region" : "#{DATAFLOW_REGION}",
      "#{DATAFLOW_CONSTANTS[:service]}/job_name" : "#{DATAFLOW_JOB_NAME}",
      "#{DATAFLOW_CONSTANTS[:service]}/job_id" : "#{DATAFLOW_JOB_ID}"
    }
    label_map { "step": "#{DATAFLOW_CONSTANTS[:service]}/step_id" }
  )

  CONFIG_ML = %(
    subservice_name "#{ML_CONSTANTS[:service]}"
    labels {
      "#{ML_CONSTANTS[:service]}/job_id" : "#{ML_JOB_ID}",
      "#{ML_CONSTANTS[:service]}/task_name" : "#{ML_TASK_NAME}",
      "#{ML_CONSTANTS[:service]}/trial_id" : "#{ML_TRIAL_ID}"
    }
    label_map { "name": "#{ML_CONSTANTS[:service]}/job_id/log_area" }
  )

  CONFIG_CUSTOM_TRACE_KEY_SPECIFIED = %(
    trace_key custom_trace_key
  )

  # Service configurations for various services.

  # GCE.
  COMPUTE_PARAMS = {
    resource: {
      type: COMPUTE_CONSTANTS[:resource_type],
      labels: {
        'instance_id' => VM_ID,
        'zone' => ZONE
      }
    },
    log_name: 'test',
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }
  COMPUTE_PARAMS_WITH_METADATA_VM_ID_AND_ZONE = COMPUTE_PARAMS.merge(
    resource: COMPUTE_PARAMS[:resource].merge(
      labels: {
        'instance_id' => METADATA_VM_ID,
        'zone' => METADATA_ZONE
      }
    )
  )

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
  }

  # GKE Container.
  CONTAINER_TAG = "kubernetes.#{CONTAINER_POD_NAME}_" \
                  "#{CONTAINER_NAMESPACE_NAME}_#{CONTAINER_CONTAINER_NAME}"

  CONTAINER_FROM_METADATA_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => CONTAINER_CLUSTER_NAME,
        'namespace_id' => CONTAINER_NAMESPACE_ID,
        'instance_id' => VM_ID,
        'pod_id' => CONTAINER_POD_ID,
        'container_name' => CONTAINER_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: CONTAINER_CONTAINER_NAME,
    project_id: PROJECT_ID,
    labels: {
      "#{GKE_CONSTANTS[:service]}/namespace_name" =>
        CONTAINER_NAMESPACE_NAME,
      "#{GKE_CONSTANTS[:service]}/pod_name" => CONTAINER_POD_NAME,
      "#{GKE_CONSTANTS[:service]}/stream" => CONTAINER_STREAM,
      "label/#{CONTAINER_LABEL_KEY}" => CONTAINER_LABEL_VALUE,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }

  # Almost the same as from metadata, but namespace_id and pod_id come from
  # namespace and pod names.
  CONTAINER_FROM_TAG_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => CONTAINER_CLUSTER_NAME,
        'namespace_id' => CONTAINER_NAMESPACE_NAME,
        'instance_id' => VM_ID,
        'pod_id' => CONTAINER_POD_NAME,
        'container_name' => CONTAINER_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: CONTAINER_CONTAINER_NAME,
    project_id: PROJECT_ID,
    labels: {
      "#{GKE_CONSTANTS[:service]}/namespace_name" =>
        CONTAINER_NAMESPACE_NAME,
      "#{GKE_CONSTANTS[:service]}/pod_name" => CONTAINER_POD_NAME,
      "#{GKE_CONSTANTS[:service]}/stream" => CONTAINER_STREAM,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }

  CONTAINER_FROM_APPLICATION_PARAMS = {
    resource: {
      type: GKE_CONSTANTS[:resource_type],
      labels: {
        'cluster_name' => CONTAINER_CLUSTER_NAME,
        'namespace_id' => CONTAINER_NAMESPACE_ID,
        'instance_id' => VM_ID,
        'pod_id' => CONTAINER_POD_ID,
        'container_name' => CONTAINER_CONTAINER_NAME,
        'zone' => ZONE
      }
    },
    log_name: 'redis',
    project_id: PROJECT_ID,
    labels: {
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }

  # Docker Container.
  DOCKER_CONTAINER_PARAMS = {
    resource: {
      type: DOCKER_CONSTANTS[:resource_type],
      labels: {
        'container_id' => DOCKER_CONTAINER_ID,
        'location' => ZONE
      }
    },
    log_name: 'test',
    project_id: PROJECT_ID,
    labels: {
      "#{DOCKER_CONSTANTS[:service]}/stream" => DOCKER_CONTAINER_STREAM_STDOUT
    }
  }
  DOCKER_CONTAINER_PARAMS_STREAM_STDERR = DOCKER_CONTAINER_PARAMS.merge(
    labels: DOCKER_CONTAINER_PARAMS[:labels].merge(
      "#{DOCKER_CONSTANTS[:service]}/stream" => DOCKER_CONTAINER_STREAM_STDERR
    )
  )
  DOCKER_CONTAINER_PARAMS_NO_STREAM = DOCKER_CONTAINER_PARAMS.merge(labels: {})

  # Cloud Functions.
  CLOUDFUNCTIONS_TAG = "kubernetes.#{CLOUDFUNCTIONS_POD_NAME}_" \
                        "#{CLOUDFUNCTIONS_NAMESPACE_NAME}_" \
                        "#{CLOUDFUNCTIONS_CONTAINER_NAME}"

  CLOUDFUNCTIONS_PARAMS = {
    resource: {
      type: CLOUDFUNCTIONS_CONSTANTS[:resource_type],
      labels: {
        'function_name' => CLOUDFUNCTIONS_FUNCTION_NAME,
        'region' => CLOUDFUNCTIONS_REGION
      }
    },
    log_name: 'cloud-functions',
    project_id: PROJECT_ID,
    labels: {
      'execution_id' => CLOUDFUNCTIONS_EXECUTION_ID,
      "#{GKE_CONSTANTS[:service]}/instance_id" => VM_ID,
      "#{GKE_CONSTANTS[:service]}/cluster_name" =>
        CLOUDFUNCTIONS_CLUSTER_NAME,
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }

  CLOUDFUNCTIONS_TEXT_NOT_MATCHED_PARAMS = {
    resource: {
      type: CLOUDFUNCTIONS_CONSTANTS[:resource_type],
      labels: {
        'function_name' => CLOUDFUNCTIONS_FUNCTION_NAME,
        'region' => CLOUDFUNCTIONS_REGION
      }
    },
    log_name: 'cloud-functions',
    project_id: PROJECT_ID,
    labels: {
      "#{GKE_CONSTANTS[:service]}/instance_id" => VM_ID,
      "#{GKE_CONSTANTS[:service]}/cluster_name" =>
        CLOUDFUNCTIONS_CLUSTER_NAME,
      "#{COMPUTE_CONSTANTS[:service]}/resource_id" => VM_ID,
      "#{COMPUTE_CONSTANTS[:service]}/resource_name" => HOSTNAME,
      "#{COMPUTE_CONSTANTS[:service]}/zone" => ZONE
    }
  }

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
  }

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
  }

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
  }

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
  }

  EC2_PARAMS = {
    resource: {
      type: EC2_CONSTANTS[:resource_type],
      labels: {
        'instance_id' => EC2_VM_ID,
        'region' => EC2_PREFIXED_ZONE,
        'aws_account' => EC2_ACCOUNT_ID
      }
    },
    log_name: 'test',
    project_id: EC2_PROJECT_ID,
    labels: {
      "#{EC2_CONSTANTS[:service]}/resource_name" => HOSTNAME
    }
  }

  HTTP_REQUEST_MESSAGE = {
    'requestMethod' => 'POST',
    'requestUrl' => 'http://example/',
    'requestSize' => 210,
    'status' => 200,
    'responseSize' => 65,
    'userAgent' => 'USER AGENT 1.0',
    'remoteIp' => '55.55.55.55',
    'referer' => 'http://referer/',
    'cacheHit' => true,
    'cacheValidatedWithOriginServer' => true
  }

  SOURCE_LOCATION_MESSAGE = {
    'file' => 'source/file',
    'function' => 'my_function',
    'line' => 18
  }

  OPERATION_MESSAGE = {
    'id' => 'op_id',
    'producer' => 'my/app',
    'last' => true
  }

  CUSTOM_LABELS_MESSAGE = {
    'customKey' => 'value'
  }
  CONFLICTING_LABEL_KEY = "#{COMPUTE_CONSTANTS[:service]}/resource_name"

  # Tags and their sanitized and encoded version.
  VALID_TAGS = {
    'test' => 'test',
    'germanß' => 'german%C3%9F',
    'chinese中' => 'chinese%E4%B8%AD',
    'specialCharacter/_-.' => 'specialCharacter%2F_-.',
    'abc@&^$*' => 'abc%40%26%5E%24%2A',
    '@&^$*' => '%40%26%5E%24%2A'
  }
  INVALID_TAGS = {
    # Non-string tags.
    123 => '123',
    1.23 => '1.23',
    [1, 2, 3] => '%5B1%2C%202%2C%203%5D',
    { key: 'value' } => '%7B%22key%22%3D%3E%22value%22%7D',
    # Non-utf8 string tags.
    "nonutf8#{[0x92].pack('C*')}" => 'nonutf8%20',
    "abc#{[0x92].pack('C*')}" => 'abc%20',
    "#{[0x92].pack('C*')}" => '%20',
    # Empty string tag.
    '' => '_'
  }
  ALL_TAGS = VALID_TAGS.merge(INVALID_TAGS)

  # Stub value for Monitored resources from Metadata Agent.
  # Map from the local_resource_id to the retrieved monitored resource.
  MONITORED_RESOURCE_STUBS = {
    # Docker container stderr / stdout logs.
    "container.#{DOCKER_CONTAINER_ID}" =>
      {
        'type' => DOCKER_CONSTANTS[:resource_type],
        'labels' => {
          'location' => ZONE,
          'container_id' => DOCKER_CONTAINER_ID
        }
      }.to_json,
    # Docker container application logs.
    "containerName.#{DOCKER_CONTAINER_NAME}" =>
      {
        'type' => DOCKER_CONSTANTS[:resource_type],
        'labels' => {
          'location' => ZONE,
          'container_id' => DOCKER_CONTAINER_ID
        }
      }.to_json,
    # GKE container logs.
    "gke_containerName.#{CONTAINER_NAMESPACE_ID}.#{CONTAINER_POD_NAME}." \
    "#{CONTAINER_CONTAINER_NAME}" =>
      {
        'type' => GKE_CONSTANTS[:resource_type],
        'labels' => {
          'cluster_name' => CONTAINER_CLUSTER_NAME,
          'container_name' => CONTAINER_CONTAINER_NAME,
          'instance_id' => VM_ID,
          'namespace_id' => CONTAINER_NAMESPACE_ID,
          'pod_id' => CONTAINER_POD_ID,
          'zone' => ZONE
        }
      }.to_json
  }

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
  }.to_json
end
