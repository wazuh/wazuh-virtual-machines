"""
AWS Credential Manager for Wazuh VM Tester.
"""

import os
from enum import Enum

import boto3
from botocore.exceptions import ClientError

from ..utils.logger import get_logger

logger = get_logger(__name__)


class AWSRole(Enum):
    """Roles available to assume in AWS."""

    QA = "qa"
    DEV = "dev"
    DEFAULT = "default"


class AWSCredentialsManager:
    """AWS Credential Manager."""

    def __init__(self):
        """Initializes the credential manager."""
        self.profiles = {
            "qa": os.environ.get("AWS_QA_PROFILE", "qa"),
            "dev": os.environ.get("AWS_DEV_PROFILE", "dev"),
            "default": os.environ.get("AWS_DEFAULT_PROFILE", "default"),
        }
        self.role_arns = {
            "default": os.environ.get("AWS_IAM_OVA_ROLE"),
        }
        self.is_github_actions = "GITHUB_ACTIONS" in os.environ

    def get_credentials(self, role_type: AWSRole = AWSRole.DEFAULT) -> tuple[str, str | None]:
        """Gets the profile and role ARN based on the action type.

        Args:
            role_type: Type of role to assume (QA, DEV, DEFAULT)

        Returns:
            Tuple containing (profile, role_arn)
        """
        role_name = role_type.value

        # If we are in GitHub Actions, we use the configured ARN role
        if self.is_github_actions:
            if role_name in ["default"] and self.role_arns.get(role_name):
                logger.info(f"Using ARN role for {role_name} in GitHub Actions")
                return self.profiles[role_name], self.role_arns[role_name]
            else:
                logger.info("Using default credentials in GitHub Actions")
                return None, None

        # If we are local, we use the profile configured in ~/.aws/credentials
        logger.info(f"Using local profile: {self.profiles[role_name]}")
        return self.profiles[role_name], None

    def create_session(
        self, profile: str | None = None, role_arn: str | None = None, region: str = "us-east-1"
    ) -> boto3.Session:
        """Create a boto3 session.

        Args:
            profile: Profile to use
            role_arn: ARN of the role to assume
            region: AWS Region

        Returns:
            boto3 session
        """
        try:
            if self.is_github_actions:
                if role_arn:
                    logger.info(f"Asume role: {role_arn}")
                    sts_client = boto3.client("sts", region_name=region)
                    assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="WazuhVMTester")
                    credentials = assumed_role["Credentials"]

                    return boto3.Session(
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                        region_name=region,
                    )
                else:
                    logger.info("Using default GitHub Actions credentials")
                    return boto3.Session(region_name=region)

            # If we are local
            if profile:
                logger.info(f"Creating a session with a local profile: {profile}")
                return boto3.Session(profile_name=profile, region_name=region)
            else:
                logger.info("Creating a session with default credentials")
                return boto3.Session(region_name=region)

        except ClientError as e:
            logger.error(f"Error creating AWS session: {e}")
            logger.info("Trying with default credentials")
            return boto3.Session(region_name=region)
