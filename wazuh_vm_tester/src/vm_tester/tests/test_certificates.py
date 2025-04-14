"""
Tests for Wazuh certificates.
"""

import os
import pytest
from datetime import datetime

from ..config import AMITesterConfig, get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """
    expected_version = os.environ.get("WAZUH_EXPECTED_VERSION")
    expected_revision = os.environ.get("WAZUH_EXPECTED_REVISION")

    return AMITesterConfig(
        expected_version=expected_version,
        expected_revision=expected_revision
    )


@pytest.mark.certificates
class TestCertificates:
    """Tests for Wazuh certificates."""

    def test_certificates_exist(self, config: AMITesterConfig):
        """Test that all required certificates exist."""
        connection = get_connection()

        failures = []

        for cert_config in config.certificates:
            cert_path = cert_config.path
            logger.info(f"Testing if certificate exists: {cert_path}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                failures.append(f"Certificate {cert_path} does not exist")
                logger.warning(f"Certificate {cert_path} does not exist")

        if failures:
            assert False, "\n".join(failures)

    def test_certificates_validity(self, config: AMITesterConfig):
        """Test that certificates are valid and not expired."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            cert_path = cert_config.path
            logger.info(f"Testing certificate validity: {cert_path}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping validity check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping validity check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -checkend 0"
            )

            if exit_code != 0:
                failures.append(f"Certificate {cert_path} has expired or is invalid: {stderr}")
                logger.warning(f"Certificate {cert_path} has expired or is invalid: {stderr}")
                continue

            # Check days remaining
            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -enddate | cut -d= -f2"
            )

            if exit_code != 0 or not stdout.strip():
                failures.append(f"Could not get end date for certificate {cert_path}: {stderr}")
                logger.warning(f"Could not get end date for certificate {cert_path}: {stderr}")
                continue

            end_date_str = stdout.strip()
            try:
                end_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()
                days_remaining = (end_date - now).days

                # Verify certificate has enough days remaining
                if days_remaining < cert_config.days_valid:
                    failures.append(
                        f"Certificate {cert_path} will expire in {days_remaining} days "
                        f"(less than the required {cert_config.days_valid} days)"
                    )
                    logger.warning(
                        f"Certificate {cert_path} will expire in {days_remaining} days "
                        f"(less than the required {cert_config.days_valid} days)"
                    )
                else:
                    logger.info(
                        f"Certificate {cert_path} has {days_remaining} days remaining "
                        f"(requirement: {cert_config.days_valid} days)"
                    )
            except ValueError as e:
                failures.append(f"Could not parse certificate end date: {end_date_str}")
                logger.warning(f"Could not parse certificate end date: {end_date_str}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)

    def test_certificate_subjects(self, config: AMITesterConfig):
        """Test certificate subjects match expected values."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            if not cert_config.subject_match:
                continue

            cert_path = cert_config.path
            subject_match = cert_config.subject_match
            logger.info(f"Testing certificate subject: {cert_path} - should match {subject_match}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping subject check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping subject check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -subject"
            )

            if exit_code != 0:
                failures.append(f"Error getting subject from certificate {cert_path}: {stderr}")
                logger.warning(f"Error getting subject from certificate {cert_path}: {stderr}")
                continue

            subject = stdout.strip()

            if subject_match.lower() not in subject.lower():
                failures.append(f"Certificate subject {subject} does not match expected pattern {subject_match}")
                logger.warning(f"Certificate subject {subject} does not match expected pattern {subject_match}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)

    def test_certificate_issuers(self, config: AMITesterConfig):
        """Test certificate issuers match expected values."""
        connection = get_connection()

        failures = []
        skipped_certs = []

        for cert_config in config.certificates:
            if not cert_config.issuer_match:
                continue

            cert_path = cert_config.path
            issuer_match = cert_config.issuer_match
            logger.info(f"Testing certificate issuer: {cert_path} - should match {issuer_match}")

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skipped_certs.append(f"Certificate {cert_path} does not exist - skipping issuer check")
                logger.warning(f"Certificate {cert_path} does not exist - skipping issuer check")
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -issuer"
            )

            if exit_code != 0:
                failures.append(f"Error getting issuer from certificate {cert_path}: {stderr}")
                logger.warning(f"Error getting issuer from certificate {cert_path}: {stderr}")
                continue

            issuer = stdout.strip()

            if issuer_match.lower() not in issuer.lower():
                failures.append(f"Certificate issuer {issuer} does not match expected pattern {issuer_match}")
                logger.warning(f"Certificate issuer {issuer} does not match expected pattern {issuer_match}")

        if skipped_certs and not failures:
            pytest.skip("\n".join(skipped_certs))

        if failures:
            assert False, "\n".join(failures)
