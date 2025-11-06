"""
EC2 client for AWS operations with role assumption support.
"""

import time
from typing import Any

from botocore.exceptions import ClientError

from ..utils.logger import get_logger
from .credentials import AWSCredentialsManager, AWSRole

logger = get_logger(__name__)


class EC2Client:
    """Client for managing EC2 instances."""

    def __init__(self, region: str, role_type: AWSRole = AWSRole.DEFAULT):
        """Initialize the client with the specified region.

        Args:
            region: AWS region
            role_type: Role type to asume (QA, DEV, DEFAULT)
        """
        self.region = region
        self.credentials_manager = AWSCredentialsManager()

        profile, role_arn = self.credentials_manager.get_credentials(role_type)

        session = self.credentials_manager.create_session(profile, role_arn, region)

        self.ec2 = session.client("ec2")

        logger.info(f"EC2Client for region {region}")
        if role_arn:
            logger.info(f"Using role: {role_arn}")
        elif profile:
            logger.info(f"Using profile: {profile}")

    def launch_instance(
        self,
        ami_id: str,
        instance_type: str = "t3.medium",
        security_group_ids: list[str] = None,
        tags: dict[str, str] = None,
        instance_profile: str | None = None,
        key_name: str | None = None,
        wait: bool = True,
        wait_timeout: int = 300,
    ) -> Any | None:
        """Launch an EC2 instance from the specified AMI.

        Args:
            ami_id: AMI ID
            instance_type: EC2 instance type
            security_group_ids: List of security group IDs (optional)
            tags: Dictionary of instance tags (optional)
            instance_profile: Instance profile name (optional)
            key_name: Name of the key pair to use (optional)
            wait: Whether to wait for the instance to be running
            wait_timeout: Timeout in seconds for waiting

        Returns:
            EC2Instance object or None if launch fails

        Raises:
            ClientError: If there's an error launching the instance
        """
        if security_group_ids is None:
            security_group_ids = []

        if tags is None:
            tags = {}

        # Add Name
        if "Name" not in tags:
            tags["Name"] = f"wazuh-vm-test-{int(time.time())}"

        # Ensure tags are in the format expected by AWS
        formatted_tags = [{"Key": k, "Value": v} for k, v in tags.items()]

        run_args = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": formatted_tags,
                }
            ],
        }

        if security_group_ids:
            run_args["SecurityGroupIds"] = security_group_ids

        if instance_profile:
            run_args["IamInstanceProfile"] = {"Name": instance_profile}

        if key_name:
            run_args["KeyName"] = key_name

        try:
            logger.info(f"Launching instance from AMI {ami_id}")
            response = self.ec2.run_instances(**run_args)
            instance_id = response["Instances"][0]["InstanceId"]
            logger.info(f"Instance {instance_id} launched successfully")

            if wait:
                logger.info(f"Waiting for instance {instance_id} to be running...")
                self.ec2.get_waiter("instance_running").wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 5, "MaxAttempts": wait_timeout // 5},
                )
                logger.info(f"Instance {instance_id} is now running")

                # Get updated instance information
                instance_info = self.get_instance_info(instance_id)
                if instance_info:
                    from ..instances.ec2_instance import EC2Instance

                    return EC2Instance(
                        instance_id=instance_id,
                        region=self.region,
                        public_ip=instance_info.get("PublicIpAddress"),
                        private_ip=instance_info.get("PrivateIpAddress"),
                    )
            else:
                from ..instances.ec2_instance import EC2Instance

                return EC2Instance(
                    instance_id=instance_id,
                    region=self.region,
                )

        except ClientError as e:
            logger.error(f"Error launching instance: {e}")
            raise

        return None

    def get_instance_info(self, instance_id: str) -> dict | None:
        """Get detailed information about an EC2 instance.

        Args:
            instance_id: EC2 instance ID

        Returns:
            Dictionary with instance information or None if not found
        """
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            reservations = response.get("Reservations", [])
            if not reservations:
                return None

            instances = reservations[0].get("Instances", [])
            if not instances:
                return None

            return instances[0]
        except ClientError as e:
            logger.error(f"Error getting instance information for {instance_id}: {e}")
            return None

    def terminate_instance(self, instance_id: str, wait: bool = True) -> bool:
        """Terminate an EC2 instance.

        Args:
            instance_id: EC2 instance ID
            wait: Whether to wait for the instance to be terminated

        Returns:
            True if termination was successful, False otherwise
        """
        try:
            logger.info(f"Terminating instance {instance_id}")
            self.ec2.terminate_instances(InstanceIds=[instance_id])

            if wait:
                logger.info(f"Waiting for instance {instance_id} to be terminated...")
                self.ec2.get_waiter("instance_terminated").wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 5, "MaxAttempts": 60},
                )
                logger.info(f"Instance {instance_id} terminated successfully")

            return True
        except ClientError as e:
            logger.error(f"Error terminating instance {instance_id}: {e}")
            return False

    def get_ami_info(self, ami_id: str) -> dict | None:
        """Get detailed information about an AMI.

        Args:
            ami_id: AMI ID

        Returns:
            Dictionary with AMI information or None if not found
        """
        try:
            response = self.ec2.describe_images(ImageIds=[ami_id])
            images = response.get("Images", [])
            if not images:
                return None

            return images[0]
        except ClientError as e:
            logger.error(f"Error getting AMI information for {ami_id}: {e}")
            return None

    def update_instance_security_groups(
        self, instance_id: str, security_group_ids: list[str], append: bool = False
    ) -> bool:
        """Update the security groups of an existing EC2 instance.

        Args:
            instance_id: EC2 instance ID
            security_group_ids: List of security group IDs to assign to the instance
            append: If True, adds the security groups to existing ones. If False, replaces them.

        Returns:
            True if security groups were updated successfully, False otherwise
        """
        if not security_group_ids:
            logger.warning(f"No security groups provided to update instance {instance_id}")
            return False

        try:
            logger.info(f"{'Adding' if append else 'Setting'} security groups for instance {instance_id}")

            instance_info = self.get_instance_info(instance_id)
            if not instance_info:
                logger.error(f"Instance {instance_id} not found")
                return False

            if append:
                try:
                    current_security_groups = []
                    for sg in instance_info.get("SecurityGroups", []):
                        if "GroupId" in sg:
                            current_security_groups.append(sg["GroupId"])

                    # Combine existing and new security groups
                    combined_groups = list(set(current_security_groups + security_group_ids))
                    security_group_ids = combined_groups

                    logger.info(f"Adding to existing security groups. Combined list: {security_group_ids}")
                except Exception as e:
                    logger.warning(f"Error getting current security groups: {e}. Will replace instead of append.")
                    append = False

            # Set new security groups
            self.ec2.modify_instance_attribute(InstanceId=instance_id, Groups=security_group_ids)

            logger.info(f"Security groups updated for instance {instance_id}: {security_group_ids}")
            return True
        except ClientError as e:
            logger.error(f"Error updating security groups for instance {instance_id}: {e}")
            return False

    def add_security_groups(self, instance_id: str, security_group_ids: list[str]) -> bool:
        """Add security groups to an existing EC2 instance without removing existing ones.

        Args:
            instance_id: EC2 instance ID
            security_group_ids: List of security group IDs to add to the instance

        Returns:
            True if security groups were added successfully, False otherwise
        """
        return self.update_instance_security_groups(instance_id, security_group_ids, append=True)
