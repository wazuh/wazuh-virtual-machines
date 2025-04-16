"""
Tests for Wazuh certificates.
"""

import os
import pytest
from datetime import datetime

from ..config import AMITesterConfig
from ..utils.logger import get_logger
from ..connections.pytest_connector import get_connection

logger = get_logger(__name__)


@pytest.fixture(scope="module")
def config() -> AMITesterConfig:
    """Create test configuration from environment variables.

    Returns:
        AMITesterConfig with expected values
    """

    return AMITesterConfig()
@pytest.mark.certificates
class TestCertificates:
    """Tests for Wazuh certificates."""

    def test_certificates_exist(self, config: AMITesterConfig):
        """Test that all required certificates exist."""
        connection = get_connection()

        existing_certificates = []
        missing_certificates = []
        message = ""

        for cert_config in config.certificates:
            cert_path = cert_config.path

            check_result = f"Certificate: {cert_path}"
            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() == "EXISTS":
                check_result += " exists"
                existing_certificates.append(check_result)
            else:
                check_result += " does NOT exist"
                missing_certificates.append(check_result)

        if existing_certificates or missing_certificates:
            message = "Certificate existence check results:\n\n"

        if existing_certificates:
            message += "Existing certificates:\n- " + "\n- ".join(existing_certificates) + "\n\n"

        if missing_certificates:
            message += "Missing certificates:\n- " + "\n- ".join(missing_certificates) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if missing_certificates:
            assert False, "One or more certificates do not exist. " + message
        else:
            assert True, "All certificates exist. " + message

    def test_certificates_validity(self, config: AMITesterConfig):
        """Test that certificates are valid and not expired."""
        connection = get_connection()

        valid_certificates = []
        invalid_certificates = []
        skipped_certificates = []
        message = ""

        for cert_config in config.certificates:
            cert_path = cert_config.path

            base_check_result = f"Certificate: {cert_path}"

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skip_result = base_check_result + " does not exist - skipping validity check"
                skipped_certificates.append(skip_result)
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -checkend 0"
            )

            check_result = base_check_result

            if exit_code != 0:
                check_result += f" has expired or is invalid: {stderr}"
                invalid_certificates.append(check_result)
                continue

            # Comprobar días restantes
            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -enddate | cut -d= -f2"
            )

            if exit_code != 0 or not stdout.strip():
                check_result += f" - could not get end date: {stderr}"
                invalid_certificates.append(check_result)
                continue

            end_date_str = stdout.strip()
            try:
                end_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()
                days_remaining = (end_date - now).days

                if days_remaining < cert_config.days_valid:
                    check_result += f" will expire in {days_remaining} days (less than required {cert_config.days_valid} days)"
                    invalid_certificates.append(check_result)
                else:
                    check_result += f" is valid with {days_remaining} days remaining (requirement: {cert_config.days_valid} days)"
                    valid_certificates.append(check_result)
            except ValueError:
                check_result += f" - could not parse end date: '{end_date_str}'"
                invalid_certificates.append(check_result)

        if valid_certificates or invalid_certificates or skipped_certificates:
            message = "Certificate validity check results:\n\n"

        if valid_certificates:
            message += "Valid certificates:\n- " + "\n- ".join(valid_certificates) + "\n\n"

        if invalid_certificates:
            message += "Invalid certificates:\n- " + "\n- ".join(invalid_certificates) + "\n\n"

        if skipped_certificates:
            message += "Skipped certificates:\n- " + "\n- ".join(skipped_certificates) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if skipped_certificates and not invalid_certificates:
            pytest.skip("Some certificates were skipped. " + message)

        if invalid_certificates:
            assert False, "One or more certificates are invalid or expiring soon. " + message
        else:
            assert True, "All certificates are valid and have sufficient time before expiration. " + message

    def test_certificate_subjects(self, config: AMITesterConfig):
        """Test certificate subjects match expected values."""
        connection = get_connection()

        matching_subjects = []
        mismatched_subjects = []
        skipped_certificates = []
        message = ""

        for cert_config in config.certificates:
            if not cert_config.subject_match:
                continue

            cert_path = cert_config.path
            subject_match = cert_config.subject_match

            base_check_result = f"Certificate: {cert_path} (expected subject pattern: {subject_match})"

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skip_result = base_check_result + " - certificate does not exist, skipping subject check"
                skipped_certificates.append(skip_result)
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -subject"
            )

            check_result = base_check_result

            if exit_code != 0:
                check_result += f" - error getting subject: {stderr}"
                mismatched_subjects.append(check_result)
                continue

            subject = stdout.strip()
            check_result += f" - actual subject: {subject}"

            if subject_match.lower() in subject.lower():
                check_result += " - MATCH"
                matching_subjects.append(check_result)
            else:
                check_result += " - NO MATCH"
                mismatched_subjects.append(check_result)

        if matching_subjects or mismatched_subjects or skipped_certificates:
            message = "Certificate subject check results:\n\n"

        if matching_subjects:
            message += "Matching subjects:\n- " + "\n- ".join(matching_subjects) + "\n\n"

        if mismatched_subjects:
            message += "Mismatched subjects:\n- " + "\n- ".join(mismatched_subjects) + "\n\n"

        if skipped_certificates:
            message += "Skipped certificates:\n- " + "\n- ".join(skipped_certificates) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if skipped_certificates and not mismatched_subjects:
            pytest.skip("Some certificates were skipped. " + message)

        if mismatched_subjects:
            assert False, "One or more certificate subjects do not match expected patterns. " + message
        else:
            assert True, "All certificate subjects match expected patterns. " + message

    def test_certificate_issuers(self, config: AMITesterConfig):
        """Test certificate issuers match expected values."""
        connection = get_connection()

        matching_issuers = []
        mismatched_issuers = []
        skipped_certificates = []
        message = ""
        check_result = ""

        for cert_config in config.certificates:
            if not cert_config.issuer_match:
                continue

            cert_path = cert_config.path
            issuer_match = cert_config.issuer_match

            base_check_result = f"Certificate: {cert_path} (expected issuer pattern: {issuer_match})"

            exit_code, stdout, _ = connection.execute_command(
                f"test -f {cert_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )

            if stdout.strip() != "EXISTS":
                skip_result = base_check_result + " - certificate does not exist, skipping issuer check"
                skipped_certificates.append(skip_result)
                continue

            exit_code, stdout, stderr = connection.execute_command(
                f"openssl x509 -in {cert_path} -noout -issuer"
            )

            check_result = base_check_result

            if exit_code != 0:
                check_result += f" - error getting issuer: {stderr}"
                mismatched_issuers.append(check_result)
                continue

            issuer = stdout.strip()
            check_result += f" - actual issuer: {issuer}"

            if issuer_match.lower() in issuer.lower():
                check_result += " - MATCH"
                matching_issuers.append(check_result)
            else:
                check_result += " - NO MATCH"
                mismatched_issuers.append(check_result)

        if matching_issuers or mismatched_issuers or skipped_certificates:
            message = "Certificate issuer check results:\n\n"

        if matching_issuers:
            message += "Matching issuers:\n- " + "\n- ".join(matching_issuers) + "\n\n"

        if mismatched_issuers:
            message += "Mismatched issuers:\n- " + "\n- ".join(mismatched_issuers) + "\n\n"

        if skipped_certificates:
            message += "Skipped certificates:\n- " + "\n- ".join(skipped_certificates) + "\n\n"

        print("\nTEST_DETAIL_MARKER:" + message)

        if skipped_certificates and not mismatched_issuers:
            pytest.skip("Some certificates were skipped. " + message)

        if mismatched_issuers:
            assert False, "One or more certificate issuers do not match expected patterns. " + message
        else:
            assert True, "All certificate issuers match expected patterns. " + message
