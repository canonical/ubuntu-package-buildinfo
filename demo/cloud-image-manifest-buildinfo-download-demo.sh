#!/bin/bash

ARCHITECTURE="amd64"
UBUNUTU_RELEASE="jammy"
# download a manifest of all packages in the latest Ubuntu 22.04 Jammy minimal image from
# https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.manifest
# and extract the package names and versions from the tab separated file
minimal_image_manifest="ubuntu-22.04-minimal-cloudimg-${ARCHITECTURE}.manifest"
wget --output-document="${minimal_image_manifest}" "https://cloud-images.ubuntu.com/minimal/releases/${UBUNUTU_RELEASE}/release/${minimal_image_manifest}"

# for each line in the file that does not contain snap: get the package name and version and
# use ubuntu-package-buildinfo to get the buildinfo for that package
minimal_image_manifest_without_snaps="${minimal_image_manifest}.debsonly.manifest"
grep --invert-match "snap:" "${minimal_image_manifest}" > "${minimal_image_manifest_without_snaps}"
while IFS=$'\t' read -r package_name package_version
do
    echo "package_name: ${package_name}"
    echo "package_version: ${package_version}"
    ubuntu-package-buildinfo --series ${UBUNUTU_RELEASE} --package-version "${package_version}" --package-name "${package_name}" --package-architecture "${ARCHITECTURE}"
done < "${minimal_image_manifest_without_snaps}"
