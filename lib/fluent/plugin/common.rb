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

module Common
  # Constants for service names, resource types and etc.
  module ServiceConstants
    APPENGINE_CONSTANTS = {
      service: 'appengine.googleapis.com',
      resource_type: 'gae_app',
      metadata_attributes: %w[gae_backend_name gae_backend_version]
    }.freeze
    COMPUTE_CONSTANTS = {
      service: 'compute.googleapis.com',
      resource_type: 'gce_instance'
    }.freeze
    GKE_CONSTANTS = {
      service: 'container.googleapis.com',
      resource_type: 'gke_container',
      extra_resource_labels: %w[namespace_id pod_id container_name],
      extra_common_labels: %w[namespace_name pod_name],
      metadata_attributes: %w[cluster-name cluster-location],
      stream_severity_map: {
        'stdout' => 'INFO',
        'stderr' => 'ERROR'
      }
    }.freeze
    K8S_CONTAINER_CONSTANTS = {
      resource_type: 'k8s_container'
    }.freeze
    K8S_POD_CONSTANTS = {
      resource_type: 'k8s_pod'
    }.freeze
    K8S_NODE_CONSTANTS = {
      resource_type: 'k8s_node'
    }.freeze
    DATAFLOW_CONSTANTS = {
      service: 'dataflow.googleapis.com',
      resource_type: 'dataflow_step',
      extra_resource_labels: %w[region job_name job_id step_id]
    }.freeze
    DATAPROC_CONSTANTS = {
      service: 'cluster.dataproc.googleapis.com',
      resource_type: 'cloud_dataproc_cluster',
      metadata_attributes: %w[dataproc-cluster-uuid dataproc-cluster-name]
    }.freeze
    EC2_CONSTANTS = {
      service: 'ec2.amazonaws.com',
      resource_type: 'aws_ec2_instance'
    }.freeze
    ML_CONSTANTS = {
      service: 'ml.googleapis.com',
      resource_type: 'ml_job',
      extra_resource_labels: %w[job_id task_name]
    }.freeze

    # The map between a subservice name and a resource type.
    SUBSERVICE_MAP =
      [APPENGINE_CONSTANTS, GKE_CONSTANTS, DATAFLOW_CONSTANTS,
       DATAPROC_CONSTANTS, ML_CONSTANTS]
      .map { |consts| [consts[:service], consts[:resource_type]] }.to_h
    # Default back to GCE if invalid value is detected.
    SUBSERVICE_MAP.default = COMPUTE_CONSTANTS[:resource_type]
    SUBSERVICE_MAP.freeze

    # The map between a resource type and expected subservice attributes.
    SUBSERVICE_METADATA_ATTRIBUTES =
      [APPENGINE_CONSTANTS, GKE_CONSTANTS, DATAPROC_CONSTANTS].map do |consts|
        [consts[:resource_type], consts[:metadata_attributes].to_set]
      end.to_h.freeze
  end

  # Name of the the Google cloud logging write scope.
  LOGGING_SCOPE = 'https://www.googleapis.com/auth/logging.write'.freeze

  # Address of the metadata service.
  METADATA_SERVICE_ADDR = '169.254.169.254'.freeze

  # "enum" of Platform values
  module Platform
    OTHER = 0  # Other/unkown platform
    GCE = 1    # Google Compute Engine
    EC2 = 2    # Amazon EC2
  end

  # Utilities for managing the resource used when writing to the
  # Google API.
  class Utils
    include Common::ServiceConstants

    def initialize(log)
      @log = log
    end

    # Determine what platform we are running on by consulting the metadata
    # service (unless the user has explicitly disabled using that).
    def detect_platform(use_metadata_service)
      unless use_metadata_service
        @log.info 'use_metadata_service is false; not detecting platform'
        return Platform::OTHER
      end

      begin
        open("http://#{METADATA_SERVICE_ADDR}", proxy: false) do |f|
          if f.meta['metadata-flavor'] == 'Google'
            @log.info 'Detected GCE platform'
            return Platform::GCE
          end
          if f.meta['server'] == 'EC2ws'
            @log.info 'Detected EC2 platform'
            return Platform::EC2
          end
        end
      rescue StandardError => e
        @log.error 'Failed to access metadata service: ', error: e
      end

      @log.info 'Unable to determine platform'
      Platform::OTHER
    end

    def fetch_gce_metadata(platform, metadata_path)
      raise "Called fetch_gce_metadata with platform=#{platform}" unless
        platform == Platform::GCE

      # See https://cloud.google.com/compute/docs/metadata
      open("http://#{METADATA_SERVICE_ADDR}/computeMetadata/v1/#{metadata_path}",
           'Metadata-Flavor' => 'Google', :proxy => false, &:read)
    end

    # EC2 Metadata server returns everything in one call. Store it after the
    # first fetch to avoid making multiple calls.
    def ec2_metadata(platform)
      raise "Called ec2_metadata with platform=#{platform}" unless
        platform == Platform::EC2

      unless @ec2_metadata
        # See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        open("http://#{METADATA_SERVICE_ADDR}/latest/dynamic/instance-identity/document", proxy: false) do |f|
          contents = f.read
          @ec2_metadata = JSON.parse(contents)
        end
      end

      @ec2_metadata
    end

    # Check required variables like @project_id, @vm_id, @vm_name and @zone.
    def check_required_metadata_variables(platform, project_id, zone, vm_id)
      missing = []
      missing << 'project_id' unless project_id
      if platform != Platform::OTHER
        missing << 'zone' unless zone
        missing << 'vm_id' unless vm_id
      end
      return if missing.empty?

      raise Fluent::ConfigError,
            "Unable to obtain metadata parameters: #{missing.join(' ')}"
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it by calling metadata server directly.
    # 3. If still not set, try to obtain it from the credentials.
    def get_project_id(platform, project_id)
      project_id ||= CredentialsInfo.project_id
      project_id ||= fetch_gce_metadata(platform, 'project/project-id') if
        platform == Platform::GCE
      project_id
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it by calling metadata servers directly.
    def get_vm_id(platform, vm_id)
      vm_id ||= fetch_gce_metadata(platform, 'instance/id') if
        platform == Platform::GCE
      vm_id ||= ec2_metadata(platform)['instanceId'] if
        platform == Platform::EC2
      vm_id
    rescue StandardError => e
      @log.error 'Failed to obtain vm_id: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def get_vm_name(vm_name)
      vm_name ||= Socket.gethostname
      vm_name
    rescue StandardError => e
      @log.error 'Failed to obtain vm name: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def get_location(platform, zone, use_aws_availability_zone)
      # Response format: "projects/<number>/zones/<zone>"
      zone ||= fetch_gce_metadata(platform,
                                  'instance/zone').rpartition('/')[2] if
        platform == Platform::GCE
      aws_location_key = if use_aws_availability_zone
                           'availabilityZone'
                         else
                           'region'
                         end
      zone ||= "aws:#{ec2_metadata(platform)[aws_location_key]}" if
        platform == Platform::EC2 &&
        ec2_metadata(platform).key?(aws_location_key)
      zone
    rescue StandardError => e
      @log.error 'Failed to obtain location: ', error: e
    end

    # Create a monitored resource from type and labels.
    def create_monitored_resource(type, labels)
      Google::Apis::LoggingV2::MonitoredResource.new(
        type: type, labels: labels.to_h
      )
    end

    # Retrieve monitored resource via the legacy way.
    #
    # Note: This is just a failover plan if we fail to get metadata from
    # Metadata Agent. Thus it should be equivalent to what Metadata Agent
    # returns.
    def determine_agent_level_monitored_resource_via_legacy(
      platform, subservice_name, detect_subservice, vm_id, zone
    )
      resource_type = determine_agent_level_monitored_resource_type(
        platform, subservice_name, detect_subservice
      )
      create_monitored_resource(
        resource_type,
        determine_agent_level_monitored_resource_labels(
          platform, resource_type, vm_id, zone
        )
      )
    end

    # Determine agent level monitored resource type.
    def determine_agent_level_monitored_resource_type(
      platform, subservice_name, detect_subservice
    )
      case platform
      when Platform::OTHER
        # Unknown platform will be defaulted to GCE instance.
        COMPUTE_CONSTANTS[:resource_type]

      when Platform::EC2
        EC2_CONSTANTS[:resource_type]

      when Platform::GCE
        # Resource types determined by subservice_name config.
        return SUBSERVICE_MAP[subservice_name] if subservice_name

        # Resource types determined by detect_subservice config.
        if detect_subservice
          begin
            attributes = fetch_gce_metadata(platform,
                                            'instance/attributes/').split.to_set
            SUBSERVICE_METADATA_ATTRIBUTES.each do |resource_type, expected|
              return resource_type if attributes.superset?(expected)
            end
          rescue StandardError => e
            @log.error 'Failed to detect subservice: ', error: e
          end
        end

        # GCE instance.
        COMPUTE_CONSTANTS[:resource_type]
      end
    end

    # Determine agent level monitored resource labels based on the resource
    # type. Each resource type has its own labels that need to be filled in.
    def determine_agent_level_monitored_resource_labels(
      platform, type, vm_id, zone
    )
      case type
      # GAE app.
      when APPENGINE_CONSTANTS[:resource_type]
        return {
          'module_id' =>
            fetch_gce_metadata(platform,
                               'instance/attributes/gae_backend_name'),
          'version_id' =>
            fetch_gce_metadata(platform,
                               'instance/attributes/gae_backend_version')
        }

      # GCE.
      when COMPUTE_CONSTANTS[:resource_type]
        raise "Cannot construct a #{type} resource without vm_id and zone" \
          unless vm_id && zone

        return {
          'instance_id' => vm_id,
          'zone' => zone
        }

      # GKE container.
      when GKE_CONSTANTS[:resource_type]
        raise "Cannot construct a #{type} resource without vm_id and zone" \
          unless vm_id && zone

        return {
          'instance_id' => vm_id,
          'zone' => zone,
          'cluster_name' =>
            fetch_gce_metadata(platform, 'instance/attributes/cluster-name')
        }

      # Cloud Dataproc.
      when DATAPROC_CONSTANTS[:resource_type]
        return {
          'cluster_uuid' =>
            fetch_gce_metadata(platform,
                               'instance/attributes/dataproc-cluster-uuid'),
          'cluster_name' =>
            fetch_gce_metadata(platform,
                               'instance/attributes/dataproc-cluster-name'),
          'region' =>
            fetch_gce_metadata(platform,
                               'instance/attributes/dataproc-region')
        }

      # EC2.
      when EC2_CONSTANTS[:resource_type]
        raise "Cannot construct a #{type} resource without vm_id and zone" \
          unless vm_id && zone

        labels = {
          'instance_id' => vm_id,
          'region' => zone
        }
        labels['aws_account'] = ec2_metadata(platform)['accountId'] if
          ec2_metadata(platform).key?('accountId')
        return labels
      end

      {}
    rescue StandardError => e
      if [Platform::GCE, Platform::EC2].include?(platform)
        @log.error "Failed to set monitored resource labels for #{type}: ",
                   error: e
      end
      {}
    end

    # TODO: This functionality should eventually be available in another
    # library, but implement it ourselves for now.
    module CredentialsInfo
      # Determine the project ID from the credentials, if possible.
      # Returns the project ID (as a string) on success, or nil on failure.
      def self.project_id
        creds = Google::Auth.get_application_default(LOGGING_SCOPE)
        if creds.respond_to?(:project_id)
          return creds.project_id if creds.project_id
        end
        if creds.issuer
          id = extract_project_id(creds.issuer)
          return id unless id.nil?
        end
        if creds.client_id
          id = extract_project_id(creds.client_id)
          return id unless id.nil?
        end
        nil
      end

      # Extracts the project id (either name or number) from str and returns
      # it (as a string) on success, or nil on failure.
      #
      # Recognizes IAM format (account@project-name.iam.gserviceaccount.com)
      # as well as the legacy format with a project number at the front of the
      # string, terminated by a dash (-) which is not part of the ID, i.e.:
      # <PROJECT_ID>-<OTHER_PARTS>.apps.googleusercontent.com
      def self.extract_project_id(str)
        [/^.*@(?<project_id>.+)\.iam\.gserviceaccount\.com/,
         /^(?<project_id>\d+)-/].each do |exp|
          match_data = exp.match(str)
          return match_data['project_id'] unless match_data.nil?
        end
        nil
      end
    end
  end
end
