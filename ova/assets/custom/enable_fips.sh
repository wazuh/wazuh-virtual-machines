# Install and enable the FIPS module
attempt=0
seconds=30
max_attempts=10
yum_lockfile="/var/run/yum.pid"
while [ -f "${yum_lockfile}" ] && [ "${attempt}" -lt "${max_attempts}" ]; do
    echo "Waiting for other package managers to finish..."
    sleep "${seconds}"
    attempt=$((attempt+1))
done
sudo yum update -y
sudo yum install -y dracut-fips
sudo dracut -f

# Enable FIPS mode by adding kernel argument:
sudo /sbin/grubby --update-kernel=ALL --args="fips=1"
