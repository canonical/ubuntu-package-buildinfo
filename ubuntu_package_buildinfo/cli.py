#!/usr/bin/env python3

import faulthandler
import hashlib
import logging
import sys

import click

from launchpadlib.launchpad import Launchpad
from launchpadlib.uris import service_roots

faulthandler.enable()


def _get_binary_packages(archive, version, binary_package_name, lp_arch_series):
    binaries = archive.getPublishedBinaries(
        exact_match=True,
        version=version,
        binary_name=binary_package_name,
        distro_arch_series=lp_arch_series,
        order_by_date=True
    )
    return binaries


def _get_source_packages(archive, version, source_package_name, lp_series):
    source_packages = archive.getPublishedSources(
        exact_match=True,
        version=version,
        source_name=source_package_name,
        distro_series=lp_series,
        order_by_date=True
    )
    return source_packages


def _write_build_artifact_to_file(filename, content, message):
    with open(filename, 'w') as f:
        f.write(content)
        print(message)


def get_buildinfo(
    package_series, package_name, package_version, source_package_query=False, package_architecture="amd64"):
    """
    Get buildlinfo for a package in the Ubuntu archive.

    Downloads the buildlog, buildinfo, changes files and changelog for a package version in a series.

    It also verifies that the buildinfo file is correct based on the checksum in the .changes file.

    * First we query the Ubuntu archive for the binary package version in the specified series and pocket.
    * If the binary package version is found we download the buildlog, changes file and buildinfo file for the
        binary package version in the specified series.
    * If the binary package version is not found we query the Ubuntu archive for the source package version in the
        specified series.
    * If the source package version is found we download the buildlog, changes file and buildinfo file for the
        source package build for the specified achitecture in the specified series.
    * We then verify that the buildinfo file is correct based on the checksum in the .changes file.
    """
    if f":{package_architecture}" in package_name:
        # strip the architecture from the package name if it is present
        package_name = package_name.replace(f":{package_architecture}", "")
    # Log in to launchpad annonymously - we use launchpad to find
    # the package publish time
    launchpad = Launchpad.login_anonymously(
        "ubuntu-package-buildinfo", service_root=service_roots["production"], version="devel"
    )

    ubuntu = launchpad.distributions["ubuntu"]

    archive = ubuntu.main_archive

    lp_series = ubuntu.getSeries(name_or_version=package_series)
    lp_arch_series = lp_series.getDistroArchSeries(archtag=package_architecture)

    binary_package_build_found = False
    if not source_package_query:
        # attempt to find a binary package build of this name first
        binaries = _get_binary_packages(
            archive, package_version, package_name, lp_arch_series
        )

        if len(binaries):
            binary_package_build_found = True
            print(
                f"INFO: \tFound binary package "
                f"{package_name} {package_architecture} version {package_version} with in {package_series}."
            )
            binary_build_link = binaries[0].build_link
            binary_build = launchpad.load(binary_build_link)
            changesfile_url = binary_build.changesfile_url
            buildinfo_url = binary_build.buildinfo_url

            buildlog_url = binary_build.build_log_url
            download_and_verify_build_artifacts(buildinfo_url, buildlog_url, changesfile_url, launchpad,
                                                package_architecture, package_name, package_version)
        else:
            binary_package_build_found = False
            print(
                f"**********WARNING: \tNo binaries found for {package_name} {package_architecture} version {package_version} in {package_series} in any archive pocket."
            )

    # a source package query only has been requested or a binary package build was not found
    if source_package_query or binary_package_build_found is False:
        # attempt to find a source package build of this name
        source_packages = _get_source_packages(archive, package_version, package_name, lp_series)
        if len(source_packages):
            builds = source_packages[0].getBuilds()
            if len(builds) > 1:
                # we need to find the build for the correct architecture
                architecture_build_found = False
                for build in builds:
                    if build.arch_tag == package_architecture:
                        architecture_build_found = True
                        print(
                            f"INFO: \tFound source package "
                            f"{package_name} {package_architecture} version {package_version} with in {package_series}."
                        )
                        changesfile_url = build.changesfile_url
                        buildinfo_url = build.buildinfo_url
                        buildlog_url = build.build_log_url
                        download_and_verify_build_artifacts(buildinfo_url, buildlog_url, changesfile_url, launchpad,
                                                            package_architecture, package_name, package_version)
                if not architecture_build_found:
                    print(
                        f"**********WARNING: \tNo source package build found for {package_name} {package_architecture} version {package_version} in {package_series} in any archive pocket."
                    )
        else:
            print(
                f"**********ERROR: \tNo source packages found for {package_name} {package_architecture} version {package_version} in {package_series} in any archive pocket."
            )


def download_and_verify_build_artifacts(buildinfo_url, buildlog_url, changesfile_url, launchpad, package_architecture,
                                        package_name, package_version):
    changesfile_resp = launchpad._browser.get(changesfile_url).decode("utf-8", errors="ignore")
    buildinfo_resp = launchpad._browser.get(buildinfo_url).decode("utf-8", errors="ignore")
    buildlog_resp = launchpad._browser.get(buildlog_url).decode("utf-8", errors="ignore")
    changes_filename = changesfile_url.split("/")[-1]
    changes_msg = f"INFO: \tchanges written to {changes_filename}"
    _write_build_artifact_to_file(changes_filename, changesfile_resp, changes_msg)
    buildinfo_filename = buildinfo_url.split("/")[-1]
    buildinfo_msg = f"INFO: \tbuildinfo written to {buildinfo_filename}"
    _write_build_artifact_to_file(buildinfo_filename, buildinfo_resp, buildinfo_msg)
    buildlog_filename = f"{package_name}_{package_version}_{package_architecture}.buildlog"
    buildlog_msg = f"INFO: \tbuildlog written to {buildlog_filename}"
    _write_build_artifact_to_file(buildlog_filename, buildlog_resp, buildlog_msg)
    # find the hashes of buildinfo_filename in the changesfile_resp and verify that they match hash
    # of the buildinfo_filename file already written to disk
    sha256_checksums_found = False
    for changesfile_line in changesfile_resp.splitlines():
        if "Checksums-Sha256:" in changesfile_line:
            sha256_checksums_found = True
        if sha256_checksums_found and buildinfo_filename in changesfile_line:
            # get the hash from the changesfile_line
            changesfile_buildinfo_hash = changesfile_line.split()[0]
            # get the hash of the buildinfo content and compare it to the hash in the changes file
            sha256hash = hashlib.sha256(buildinfo_resp.encode("UTF-8")).hexdigest()
            if changesfile_buildinfo_hash == sha256hash:
                print(f"INFO: \tHash of {buildinfo_filename} matches hash in changes file.")
            else:
                print(f"**********ERROR: \tHash of {buildinfo_filename} does not match hash in changes file.")
            # we have found the hash of the buildinfo_filename in the changes file so we can stop
            # iterating over the changesfile lines
            break


@click.command()
@click.option(
    "--series",
    help="The Ubuntu series eg. '20.04' or 'focal'.",
    required=True,
)
@click.option(
    "--package-name",
    help="Package name",
    required=True,
)
@click.option(
    "--package-version",
    help="Package version",
    required=True,
)
@click.option(
    "--source-package",
    is_flag=True,
    show_default=True,
    default=False,
    help="Query source package only?",
    required=False,
)
@click.option(
    "--logging-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    required=False,
    default="ERROR",
    help="How detailed would you like the output.",
    show_default=True,
)
@click.option(
    "--package-architecture",
    help="The architecture to use when querying package "
    "version in the archive. The default is amd64. ",
    required=True,
    default="amd64",
    show_default=True,
)
@click.pass_context
def ubuntu_package_buildinfo(
    ctx, series, package_name, package_version, source_package, logging_level, package_architecture):
    # type: (Dict, Text, Text,Text, Bool, Text, Optional[Text]) -> None

    # We log to stderr so that a shell calling this will not have logging
    # output in the $() capture.
    level = logging.getLevelName(logging_level)
    logging.basicConfig(level=level, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")

    get_buildinfo(series, package_name, package_version, source_package, package_architecture)


if __name__ == "__main__":
    ubuntu_package_buildinfo(obj={})
