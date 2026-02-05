# Devops Integration Tests Results

## Summary  for AMI

**Status**: FAIL :red_circle:

| Metric | Count |
|--------|-------|
| Total Tests | 3 |
| Passed | 0 |
| Failed | 3|
| Warnings | 0 |
| Skipped | 0 |

## Failed Tests :red_circle:

### Ova

**Ova: Boot files** :red_circle:

```
self = <test_runner.tests.test_ova.TestOVA object at 0x7ff601d144c0>
config = BaseTesterConfig(test_type=<TestType.OVA: 'ova'>, test_patterns={<TestType.AMI: 'ami'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version'], <TestType.OVA: 'ova'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version', 'test_ova']}, use_local=False, ssh_host=None, existing_instance_id=None, ova_s3_path=None, ansible_inventory_path=None, ansible_host_id=None, aws_region='us-east-1', aws_role='default', ssh_username='wazuh-user', ssh_password='wazuh', ssh_key_path=None, key_name=None, ssh_private_key=None, ssh_port=22, ssh_common_args=None, instance_profile=None, default_security_group_ids=['sg-0471247ce289c863c'], security_group_ids=['sg-0471247ce289c863c'], tags={}, terminate_on_completion=True, temp_key_name=None, existing_instance=None, expected_version=None, expected_revision=None, launch_timeout=300, ssh_connect_timeout=420, service_check_timeout=60, max_retries=5, retry_delay=30, services=[WazuhServiceConfig(name='wazuh-manager', version='5.0.0', revision='latest', port=[55000], process_name='wazuh-manager', log_files=[], log_commands=['journalctl -u wazuh-manager -n 100'], required_dirs=['/var/ossec/etc', '/var/ossec/bin'], required_files=['/var/ossec/etc/ossec.conf'], version_commands=[CommandConfig(command='cat /var/ossec/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-manager --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[], api_endpoints=[EndpointConfig(url='https://localhost:55000/?pretty=true', token='https://localhost:55000/security/user/authenticate?raw=true', method='GET', auth={'username': 'wazuh', 'password': 'wazuh'}, headers={'Content-Type': 'application/json'}, expected_status=[200], expected_content=None)]), WazuhServiceConfig(name='wazuh-indexer', version='5.0.0', revision='latest', port=9200, process_name='wazuh-indexer', log_files=['/var/log/wazuh-indexer/wazuh-cluster.log'], log_commands=[], required_dirs=['/etc/wazuh-indexer'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-indexer/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost:9200/_cluster/health?pretty', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[]), WazuhServiceConfig(name='wazuh-dashboard', version='5.0.0', revision='latest', port=443, process_name='wazuh-dashboard', log_files=[], log_commands=['journalctl -u wazuh-dashboard -n 100'], required_dirs=['/etc/wazuh-dashboard'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-dashboard/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost/status', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[])], certificates=[WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/indexer.pem', subject_match='CN=wazuh_indexer', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/dashboard.pem', subject_match='CN=wazuh_dashboard', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/manager.pem', subject_match='CN=wazuh_manager', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400)], connectivity_tests=[], log_error_patterns=['ERROR:', 'CRITICAL:', 'FATAL:', 'Failed to', 'Error:', 'Could not', "Couldn't", 'Exception', 'error:', 'panic:'], log_false_positives=['ErrorDocument', 'is not an error', 'recovering from error', 'fixing error', 'error resolved'])

    def test_boot_files(self, config: BaseTesterConfig):
        """Test the existence of required boot files."""
        connection = get_connection()
    
        files_to_check = ["/boot/grub2/wazuh.png", "/boot/grub2/grub.cfg", "/etc/default/grub"]
    
        existing_files = []
        missing_files = []
    
        for file_path in files_to_check:
            check_result = f"File: {file_path}"
            exit_code, stdout, _ = connection.execute_command(
                f"test -f {file_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
            )
    
            if stdout.strip() == "EXISTS":
                check_result += " exists"
                existing_files.append(check_result)
            else:
                check_result += " does NOT exist"
                missing_files.append(check_result)
    
        message = "Boot files check results:\n\n"
    
        if existing_files:
            message += "Existing files:\n- " + "\n- ".join(existing_files) + "\n\n"
    
        if missing_files:
            message += "Missing files:\n- " + "\n- ".join(missing_files) + "\n\n"
    
        print("\nTEST_DETAIL_MARKER:" + message)
    
        if missing_files:
>           raise AssertionError("One or more required boot files do not exist. " + message)
E           AssertionError: One or more required boot files do not exist. Boot files check results:
E           
E           Existing files:
E           - File: /boot/grub2/grub.cfg exists
E           - File: /etc/default/grub exists
E           
E           Missing files:
E           - File: /boot/grub2/wazuh.png does NOT exist

../wazuh-automation/new-integration-test-module/integration-test-module/src/test_runner/tests/test_ova.py:62: AssertionError
```

**Ova: Fips enabled** :red_circle:

```
self = <test_runner.tests.test_ova.TestOVA object at 0x7ff601d15330>
config = BaseTesterConfig(test_type=<TestType.OVA: 'ova'>, test_patterns={<TestType.AMI: 'ami'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version'], <TestType.OVA: 'ova'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version', 'test_ova']}, use_local=False, ssh_host=None, existing_instance_id=None, ova_s3_path=None, ansible_inventory_path=None, ansible_host_id=None, aws_region='us-east-1', aws_role='default', ssh_username='wazuh-user', ssh_password='wazuh', ssh_key_path=None, key_name=None, ssh_private_key=None, ssh_port=22, ssh_common_args=None, instance_profile=None, default_security_group_ids=['sg-0471247ce289c863c'], security_group_ids=['sg-0471247ce289c863c'], tags={}, terminate_on_completion=True, temp_key_name=None, existing_instance=None, expected_version=None, expected_revision=None, launch_timeout=300, ssh_connect_timeout=420, service_check_timeout=60, max_retries=5, retry_delay=30, services=[WazuhServiceConfig(name='wazuh-manager', version='5.0.0', revision='latest', port=[55000], process_name='wazuh-manager', log_files=[], log_commands=['journalctl -u wazuh-manager -n 100'], required_dirs=['/var/ossec/etc', '/var/ossec/bin'], required_files=['/var/ossec/etc/ossec.conf'], version_commands=[CommandConfig(command='cat /var/ossec/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-manager --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[], api_endpoints=[EndpointConfig(url='https://localhost:55000/?pretty=true', token='https://localhost:55000/security/user/authenticate?raw=true', method='GET', auth={'username': 'wazuh', 'password': 'wazuh'}, headers={'Content-Type': 'application/json'}, expected_status=[200], expected_content=None)]), WazuhServiceConfig(name='wazuh-indexer', version='5.0.0', revision='latest', port=9200, process_name='wazuh-indexer', log_files=['/var/log/wazuh-indexer/wazuh-cluster.log'], log_commands=[], required_dirs=['/etc/wazuh-indexer'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-indexer/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost:9200/_cluster/health?pretty', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[]), WazuhServiceConfig(name='wazuh-dashboard', version='5.0.0', revision='latest', port=443, process_name='wazuh-dashboard', log_files=[], log_commands=['journalctl -u wazuh-dashboard -n 100'], required_dirs=['/etc/wazuh-dashboard'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-dashboard/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost/status', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[])], certificates=[WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/indexer.pem', subject_match='CN=wazuh_indexer', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/dashboard.pem', subject_match='CN=wazuh_dashboard', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/manager.pem', subject_match='CN=wazuh_manager', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400)], connectivity_tests=[], log_error_patterns=['ERROR:', 'CRITICAL:', 'FATAL:', 'Failed to', 'Error:', 'Could not', "Couldn't", 'Exception', 'error:', 'panic:'], log_false_positives=['ErrorDocument', 'is not an error', 'recovering from error', 'fixing error', 'error resolved'])

    def test_fips_enabled(self, config: BaseTesterConfig):
        """Test that FIPS is correctly enabled."""
        connection = get_connection()
    
        fips_file = "/proc/sys/crypto/fips_enabled"
        check_result = f"FIPS status file: {fips_file}"
    
        exit_code, stdout, _ = connection.execute_command(f"test -f {fips_file} && echo 'EXISTS' || echo 'NOT_EXISTS'")
    
        if stdout.strip() != "EXISTS":
            message = f"{check_result} does NOT exist"
            print("\nTEST_DETAIL_MARKER:" + message)
            raise AssertionError(message)
    
        exit_code, stdout, _ = connection.execute_command(f"cat {fips_file}")
    
        fips_enabled = stdout.strip() == "1"
    
        message = "FIPS is enabled" if fips_enabled else "FIPS is NOT enabled"
    
        print("\nTEST_DETAIL_MARKER:" + message)
>       assert fips_enabled, message
E       AssertionError: FIPS is NOT enabled
E       assert False

../wazuh-automation/new-integration-test-module/integration-test-module/src/test_runner/tests/test_ova.py:87: AssertionError
```

**Ova: Wazuh banner** :red_circle:

```
self = <test_runner.tests.test_ova.TestOVA object at 0x7ff601d15810>
config = BaseTesterConfig(test_type=<TestType.OVA: 'ova'>, test_patterns={<TestType.AMI: 'ami'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version'], <TestType.OVA: 'ova'>: ['test_certificates', 'test_connectivity', 'test_services', 'test_logs', 'test_version', 'test_ova']}, use_local=False, ssh_host=None, existing_instance_id=None, ova_s3_path=None, ansible_inventory_path=None, ansible_host_id=None, aws_region='us-east-1', aws_role='default', ssh_username='wazuh-user', ssh_password='wazuh', ssh_key_path=None, key_name=None, ssh_private_key=None, ssh_port=22, ssh_common_args=None, instance_profile=None, default_security_group_ids=['sg-0471247ce289c863c'], security_group_ids=['sg-0471247ce289c863c'], tags={}, terminate_on_completion=True, temp_key_name=None, existing_instance=None, expected_version=None, expected_revision=None, launch_timeout=300, ssh_connect_timeout=420, service_check_timeout=60, max_retries=5, retry_delay=30, services=[WazuhServiceConfig(name='wazuh-manager', version='5.0.0', revision='latest', port=[55000], process_name='wazuh-manager', log_files=[], log_commands=['journalctl -u wazuh-manager -n 100'], required_dirs=['/var/ossec/etc', '/var/ossec/bin'], required_files=['/var/ossec/etc/ossec.conf'], version_commands=[CommandConfig(command='cat /var/ossec/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-manager --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[], api_endpoints=[EndpointConfig(url='https://localhost:55000/?pretty=true', token='https://localhost:55000/security/user/authenticate?raw=true', method='GET', auth={'username': 'wazuh', 'password': 'wazuh'}, headers={'Content-Type': 'application/json'}, expected_status=[200], expected_content=None)]), WazuhServiceConfig(name='wazuh-indexer', version='5.0.0', revision='latest', port=9200, process_name='wazuh-indexer', log_files=['/var/log/wazuh-indexer/wazuh-cluster.log'], log_commands=[], required_dirs=['/etc/wazuh-indexer'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-indexer 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-indexer/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-indexer --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost:9200/_cluster/health?pretty', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[]), WazuhServiceConfig(name='wazuh-dashboard', version='5.0.0', revision='latest', port=443, process_name='wazuh-dashboard', log_files=[], log_commands=['journalctl -u wazuh-dashboard -n 100'], required_dirs=['/etc/wazuh-dashboard'], required_files=[], version_commands=[CommandConfig(command="rpm -q wazuh-dashboard 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null", expected_output=None, expected_regex='([\\d.]+)', expected_status=0), CommandConfig(command='cat /usr/share/wazuh-dashboard/VERSION.json', expected_output=None, expected_regex='"version":\\s*"([\\d.]+)"', expected_status=0)], revision_commands=[CommandConfig(command="rpm -q wazuh-dashboard --queryformat '%{RELEASE}' 2>/dev/null || dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null | cut -d '-' -f2", expected_output=None, expected_regex='(.+)', expected_status=0)], health_endpoints=[EndpointConfig(url='https://localhost/status', token=None, method='GET', auth={'username': 'admin', 'password': 'admin'}, headers={}, expected_status=[200], expected_content=None)], api_endpoints=[])], certificates=[WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/indexer.pem', subject_match='CN=wazuh_indexer', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-indexer/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/etc/wazuh-dashboard/certs/dashboard.pem', subject_match='CN=wazuh_dashboard', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/manager.pem', subject_match='CN=wazuh_manager', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/root-ca.pem', subject_match='OU=Wazuh', issuer_match='OU=Wazuh', days_valid=365, permissions=400), WazuhCertificateConfig(path='/var/ossec/etc/certs/admin.pem', subject_match='CN=admin', issuer_match='OU=Wazuh', days_valid=365, permissions=400)], connectivity_tests=[], log_error_patterns=['ERROR:', 'CRITICAL:', 'FATAL:', 'Failed to', 'Error:', 'Could not', "Couldn't", 'Exception', 'error:', 'panic:'], log_false_positives=['ErrorDocument', 'is not an error', 'recovering from error', 'fixing error', 'error resolved'])

    def test_wazuh_banner(self, config: BaseTesterConfig):
        """Test the existence of the Wazuh banner"""
        connection = get_connection()
    
        banner_path = "/usr/lib/motd.d/40-wazuh-banner"
        banner_dir = "/usr/lib/motd.d/"
    
        exit_code, stdout, _ = connection.execute_command(
            f"test -f {banner_path} && echo 'EXISTS' || echo 'NOT_EXISTS'"
        )
    
        banner_exists = stdout.strip() == "EXISTS"
    
        exit_code, stdout, _ = connection.execute_command(
            f"ls -la {banner_dir} | grep -v '^d' | grep -v 'total' | wc -l"
        )
    
        file_count = int(stdout.strip())
    
        is_only_file = file_count == 1
    
        message = ""
        if banner_exists:
            message += f"Wazuh banner exists at {banner_path}\n"
        else:
            message += f"Wazuh banner does NOT exist at {banner_path}\n"
    
        if is_only_file:
            message += "It is the only file in the directory"
        else:
            message += f"There are {file_count} files in the directory (should be 1)"
    
        print("\nTEST_DETAIL_MARKER:" + message)
    
>       assert banner_exists and is_only_file, message
E       AssertionError: Wazuh banner does NOT exist at /usr/lib/motd.d/40-wazuh-banner
E         There are 0 files in the directory (should be 1)
E       assert (False)

../wazuh-automation/new-integration-test-module/integration-test-module/src/test_runner/tests/test_ova.py:123: AssertionError
```

