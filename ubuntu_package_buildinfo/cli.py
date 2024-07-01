#!/usr/bin/env python3

import faulthandler
import hashlib
import logging
import os
import sys
import urllib

import click
import lazr

from launchpadlib.credentials import UnencryptedFileCredentialStore
from launchpadlib.launchpad import Launchpad
from launchpadlib.uris import service_roots

faulthandler.enable()


def _get_binary_package_publishing_histories(archive, version, binary_package_name, lp_arch_series):
    binary_publish_histories = archive.getPublishedBinaries(
        exact_match=True,
        version=version,
        binary_name=binary_package_name,
        distro_arch_series=lp_arch_series,
        order_by_date=True
    )
    return binary_publish_histories


def _get_source_package_publishing_histories(archive, version, source_package_name):
    source_packages = archive.getPublishedSources(
        exact_match=True,
        version=version,
        source_name=source_package_name,
        order_by_date=True
    )
    return source_packages


def _write_build_artifact_to_file(filename, content, message):
    with open(filename, 'w') as f:
        f.write(content)
        print(message)


def get_buildinfo(
    package_series,
    package_name,
    package_version,
    source_package_query=False,
    package_architecture="amd64",
    download=True,
    ppa=None,
    lp_user=None,
    lp_credentials_store=None
):
    """
    Get buildlinfo for a package in the Ubuntu archive.

    Downloads the buildlog, buildinfo, changes files and changelog for a package version in a series.

    It also verifies that the buildinfo file is correct based on the checksum in the .changes file.

    * First we query the Ubuntu archive (or PPA if specified) for the binary package version in the specified series and pocket.
    * If the binary package version is found we download the buildlog, changes file and buildinfo file for the
        binary package version in the specified series.
    * If the binary package version is not found we query the Ubuntu archive (or PPA if specified) for the source package version in the
        specified series.
    * If the source package version is found we download the buildlog, changes file and buildinfo file for the
        source package build for the specified achitecture in the specified series.
    * We then verify that the buildinfo file is correct based on the checksum in the .changes file.
    """
    if f":{package_architecture}" in package_name:
        # strip the architecture from the package name if it is present
        package_name = package_name.replace(f":{package_architecture}", "")

    # Is there a .buildinfo file already downloaded for this package name, version and srchitecture combination?
    predicted_buildinfo_filename = f"{package_name}_{package_version}_{package_architecture}.buildinfo"
    if os.path.exists(predicted_buildinfo_filename):
        print(f"INFO: \t{predicted_buildinfo_filename} already exists. Skipping download.")
        return

    if not lp_credentials_store:
        creds_prefix = os.environ.get("SNAP_USER_COMMON", os.path.expanduser("~"))
        store = UnencryptedFileCredentialStore(os.path.join(creds_prefix, ".launchpad.credentials"))
    else:
        store = UnencryptedFileCredentialStore(lp_credentials_store)

    if lp_user:
        launchpad = Launchpad.login_with(
            lp_user,
            credential_store=store,
            service_root=service_roots['production'], version='devel')
    else:
        # Log in to launchpad annonymously - we use launchpad to find
        # the package publish time
        launchpad = Launchpad.login_anonymously(
            "ubuntu-package-buildinfo",
            service_root=service_roots['production'], version='devel')

    ubuntu = launchpad.distributions["ubuntu"]

    archive = ubuntu.main_archive

    if ppa:
        ppa_owner_and_name = ppa.replace("ppa:", "")
        ppa_owner, ppa_name = ppa_owner_and_name.split("/")
        archive = launchpad.people[ppa_owner].getPPAByName(name=ppa_name)

    lp_series = ubuntu.getSeries(name_or_version=package_series)
    lp_arch_series = lp_series.getDistroArchSeries(archtag=package_architecture)

    binary_build = None
    # attempt to find a binary package build of this name first
    if not source_package_query:
        binary_publishing_histories = _get_binary_package_publishing_histories(
            archive, package_version, package_name, lp_arch_series
        )

        if len(binary_publishing_histories):
            # given the very specific filtering of the getPublishedBinaries query we should only have one result
            binary_build_link = binary_publishing_histories[0].build_link
            try:
                binary_build = launchpad.load(binary_build_link)
                print(
                    f"INFO: \tFound binary package "
                    f"{package_name} {package_architecture} version {package_version} in {package_series}."
                )
            except ValueError:
                print(
                    f"**********ERROR(Exception): \tCould not load binary build link {binary_build_link}."
                )
        else:
            print(
                f"**********WARNING: \tNo binary builds found for binary {package_name} {package_architecture} version {package_version} in {package_series}. Searching for source package of the same name..."
            )

    if source_package_query or binary_build is None:
        source_package_publishing_histories = _get_source_package_publishing_histories(archive, package_version, package_name)
        if len(source_package_publishing_histories):
            # iterate over the source package publishing histories and find the first one with build history.
            # This is because some package are copied from series to series without any rebuilds.
            source_package_build_for_series = False
            for source_package_publishing_history in source_package_publishing_histories:
                source_package = source_package_publishing_history
                try:
                    source_package_builds = source_package.getBuilds()
                except lazr.restfulclient.errors.Unauthorized as unauthorized_error:
                    print(
                        f"**********ERROR(Unauthorized): \tUnauthorized to access source package {package_name} {package_version} - {source_package}."
                    )
                    raise unauthorized_error
                if len(source_package_builds):
                    distro_series = launchpad.load(source_package.distro_series_link)
                    # If builds were not found in the specified series then print a message stating which series
                    # the first source package with published builds was found in.
                    if distro_series.name != package_series:
                        source_package_build_for_series = False
                    else:
                        # We have found a source package with published builds in the specified series.
                        # We can break the for loop and continue
                        source_package_build_for_series = True
                        break
            if not source_package_build_for_series:
                print(
                    f"INFO: \tFirst source package with published builds for "
                    f"{package_name} version {package_version} found in series {distro_series.name}. This occurs when a package is copied from one series to another without any rebuilds."
                )
            try:
                source_package_builds = source_package.getBuilds()
            except lazr.restfulclient.errors.Unauthorized as unauthorized_error:
                print(
                    f"**********ERROR(Unauthorized): \tUnauthorized to access source package {package_name} {package_version} - {source_package}."
                )
                raise unauthorized_error
            # Now find the build for the specified architecture and if it is not found use the amd64 build
            architecture_all_arch_tag = "amd64"
            architecture_all_build = None
            architecture_build = None
            for source_package_build in source_package_builds:
                if source_package_build.arch_tag == architecture_all_arch_tag:
                    # This will be our fallback if we do not find a build for the specified architecture
                    architecture_all_build = source_package_build
                if source_package_build.arch_tag == package_architecture:
                    architecture_build = source_package_build
                    # if we have found a build for the specified architecture then we can break
                    break

            if not source_package_query and architecture_build is None and architecture_all_build is not None:
                architecture_build = architecture_all_build
                print(f"INFO: \tNo build found for architecture {package_architecture} using {architecture_all_arch_tag} instead. This will occur if there is no build for the specified architecture and the amd64 architecture build is used instead. - when `Architecture: all` is used for example")

            if architecture_build is not None:
                binary_build = architecture_build
                print(
                    f"INFO: \tFound binary build from source package "
                    f"{package_name} {architecture_build.arch_tag} version {package_version} in {package_series}."
                )
            else:
                print(
                    f"**********WARNING: \tNo binary builds found for source package {package_name} {package_architecture} version {package_version} in {package_series}."
                )

    if binary_build:
        binary_build_architecture = binary_build.arch_tag
        if not source_package_query and binary_build_architecture != package_architecture:
            print(
                f"INFO: \tThis binary build was an {binary_build_architecture} architecture build which differs from {package_architecture} specified. This is expected and is usually due to `Architecture: all` in the debian/control file."
            )
        changesfile_url = binary_build.changesfile_url
        buildlog_url = binary_build.build_log_url
        buildinfo_url = binary_build.buildinfo_url
        build_web_link = binary_build.web_link
        if not buildinfo_url:
            print(f"**********ERROR: \tNo buildinfo found for {package_name} {package_architecture} version {package_version} in {package_series}. See {build_web_link} for more details. Source package {binary_build.source_package_name} version {binary_build.source_package_version}.")
        else:
            if download:
                download_and_verify_build_artifacts(buildinfo_url, buildlog_url, changesfile_url, launchpad,
                                                    binary_build_architecture, package_name, package_version)
    else:
        print(
            f"**********ERROR: \tNo binary builds found for {package_name} {package_architecture} version {package_version} in {package_series}."
        )


def download_and_verify_build_artifacts(buildinfo_url, buildlog_url, changesfile_url, launchpad, package_architecture,
                                        package_name, package_version):

    changesfile_api_url = launchpad._root_uri.append(urllib.parse.urlparse(changesfile_url).path.lstrip('/'))
    changesfile_resp = launchpad._browser.get(changesfile_api_url).decode('utf-8', errors="ignore")
    buildinfo_api_url = launchpad._root_uri.append(urllib.parse.urlparse(buildinfo_url).path.lstrip('/'))
    buildinfo_resp = launchpad._browser.get(buildinfo_api_url).decode("utf-8", errors="ignore")
    buildlog_api_url = launchpad._root_uri.append(urllib.parse.urlparse(buildlog_url).path.lstrip('/'))
    buildlog_resp = launchpad._browser.get(buildlog_api_url).decode("utf-8", errors="ignore")
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
@click.option(
    "--download/--no-download",
    is_flag=True,
    show_default=True,
    default=True,
    help="Download buildinfo? Setting to False is useful for testing for missing buildinfo files.",
    required=False,
)
@click.option(
    "--ppa",
    required=False,
    type=click.STRING,
    help="Additional PPAs that you wish to query for buildinfo - If specified - this is queried instead of the main Ubuntu archive."
    "Expected format is "
    "ppa:'%LAUNCHPAD_USERNAME%/%PPA_NAME%' eg. ppa:philroche/cloud-init",
)
@click.option(
    "--launchpad-user",
    "lp_user",
    required=False,
    type=click.STRING,
    help="Launchpad username to use when querying PPAs. This is important if "
         "you are querying PPAs that are not public.",
    default=None
)
@click.option(
    "--launchpad-credentials-store",
    "lp_credentials_store",
    envvar="LP_CREDENTIALS_STORE",
    required=False,
    help="An optional path to an already configured launchpad credentials store.",
    default=None,
)
@click.pass_context
def ubuntu_package_buildinfo(
    ctx, series, package_name, package_version, source_package, logging_level, package_architecture, download, ppa,
    lp_user, lp_credentials_store
):
    # type: (Dict, Text, Text,Text, Bool, Text, Text, Bool, Text, Optional[Text], Optional[Text]) -> None

    # We log to stderr so that a shell calling this will not have logging
    # output in the $() capture.
    level = logging.getLevelName(logging_level)
    logging.basicConfig(level=level, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")
    get_buildinfo(series,
                  package_name,
                  package_version,
                  source_package,
                  package_architecture,
                  download,
                  ppa,
                  lp_user,
                  lp_credentials_store)


if __name__ == "__main__":
    ubuntu_package_buildinfo(obj={})
