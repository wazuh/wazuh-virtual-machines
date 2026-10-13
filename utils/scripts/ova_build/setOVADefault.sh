
[[ ${DEBUG} = "yes" ]] && set -x

echo "Standarizing OVA"

workspace=$1
path_ova=$2
dest_ova=$3
ovf_path=$4
wazuh_version=$5
# Version shown in the appliance name and Product (e.g. 5.0.0-dev for a development build)
ova_version=${6:-${wazuh_version}}
# Download location of the OVA. The ProductUrl element is removed when empty
product_url=$7
file="wazuh-${wazuh_version}"
mkdir -p ${workspace}/new-ova/

echo "Setting OVA to default"

tar -xvf ${path_ova} --directory ${workspace}/new-ova/
echo "OVF extracted"

mv "${workspace}"/new-ova/*.ovf ${workspace}/new-ova/${file}.ovf
mv "${workspace}"/new-ova/*.vmdk ${workspace}/new-ova/${file}-disk-1.vmdk
echo "Files renamed"

cp ${ovf_path} ${workspace}/new-ova/${file}.ovf

sed -i "s/{WAZUH_VERSION}/${wazuh_version}/" ${workspace}/new-ova/${file}.ovf
sed -i "s/{OVA_VERSION}/${ova_version}/" ${workspace}/new-ova/${file}.ovf
echo "OVF Version changed"

if [ -n "${product_url}" ]; then
    sed -i "s|{PRODUCT_URL}|${product_url}|" ${workspace}/new-ova/${file}.ovf
else
    sed -i "/{PRODUCT_URL}/d" ${workspace}/new-ova/${file}.ovf
fi
echo "OVF Product URL changed"

ovf_size=$(stat --printf=%s ${workspace}/new-ova/${file}-disk-1.vmdk)
sed -i "s/{SIZE}/${ovf_size}/" "${workspace}/new-ova/${file}.ovf"
echo "OVF Size changed"

export workspace
export file
sha_ovf=$(sha1sum ${workspace}/new-ova/${file}.ovf)
sha_vmdk=$(sha1sum ${workspace}/new-ova/${file}-disk-1.vmdk)
read -a sha_ovf_array <<< "${sha_ovf}"
read -a sha_vmdk_array <<< "${sha_vmdk}"

sha_ovf=${sha_ovf_array[0]}
sha_vmdk=${sha_vmdk_array[0]}

echo "SHA1(${file}-disk-1.vmdk) = ${sha_vmdk}" > ${workspace}/new-ova/${file}.mf
echo "SHA1(${file}.ovf) = ${sha_ovf}" >> ${workspace}/new-ova/${file}.mf
echo "Manifest changed"

tar -cvf "${dest_ova}" -C "${workspace}/new-ova/" ${file}.ovf ${file}-disk-1.vmdk ${file}.mf
echo "New OVA created"

rm -rf ${workspace}/new-ova/
echo "Cleaned temporary directory"
