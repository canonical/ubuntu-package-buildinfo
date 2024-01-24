#!/usr/bin/env python3

import faulthandler
import hashlib
import logging
import re
import sys

import click

import urllib.parse
from launchpadlib.launchpad import Launchpad
from launchpadlib.uris import service_roots

# Which archive pockets are checked in order of where a recent package is most likely to be published
ARCHIVE_POCKETS = ["Updates", "Security", "Release", "Proposed"]
faulthandler.enable()


def _get_binary_packages(archive, version, binary_package_name, lp_arch_series, pocket, status="Published"):
    binaries = archive.getPublishedBinaries(
        exact_match=True,
        version=version,
        binary_name=binary_package_name,
        distro_arch_series=lp_arch_series,
        pocket=pocket,
        order_by_date=True,
        status=status,
    )
    return binaries


def _get_published_sources(archive, version, source_package_name, lp_series, pocket, status="Published"):
    sources = archive.getPublishedSources(
        exact_match=True,
        version=version,
        source_name=source_package_name,
        pocket=pocket,
        distro_series=lp_series,
        order_by_date=True,
        status=status,
    )
    return sources


def get_buildinfo(
    package_series, package_name, package_version, package_architecture="amd64", ppas=[], lp_user=None
):
    """
    Get buildlinfo for a package in the Ubuntu archive.

    Downloads the buildlog, buildinfo, changes files and changelog for a package version in a series.

    It also verifies that the buildinfo file is correct based on the checksum in the .changes file.

    * First we query the Ubuntu archive for the binary package version in the specified series and pocket.
    * If the binary package version is found we download the buildlog, changes file and buildinfo file for the
        binary package version in the specified series and pocket.
    * We then verify that the buildinfo file is correct based on the checksum in the .changes file.
    """
    if f":{package_architecture}" in package_name:
        # strip the architecture from the package name if it is present
        package_name = package_name.replace(f":{package_architecture}", "")
    if lp_user:
        launchpad = Launchpad.login_with(lp_user, service_root=service_roots["production"], version="devel")
    else:
        # Log in to launchpad annonymously - we use launchpad to find
        # the package publish time
        launchpad = Launchpad.login_anonymously(
            "ubuntu-package-buildinfo", service_root=service_roots["production"], version="devel"
        )

    ubuntu = launchpad.distributions["ubuntu"]
    build_found = False
    for pocket in ARCHIVE_POCKETS:

        # TODO add support for PPAs
        # if args.ppa:
        #     ppa_owner, ppa_name = args.ppa.split('/')
        #     archive = launchpad.people[ppa_owner].getPPAByName(name=ppa_name)
        #     if args.pocket != 'Release':
        #         print('using pocket "Release" when using a PPA ...')
        #         pocket = 'Release'
        # else:
        archive = ubuntu.main_archive

        lp_series = ubuntu.getSeries(name_or_version=package_series)
        lp_arch_series = lp_series.getDistroArchSeries(archtag=package_architecture)

        for package_publication_status in ["Published", "Superseded"]:
            # attempt to find a binary package build of this name first
            binaries = _get_binary_packages(
                archive, package_version, package_name, lp_arch_series, pocket, status=package_publication_status
            )

            if len(binaries):
                print(
                    f"INFO: \tFound binary package "
                    f"{package_name} {package_architecture} version {package_version} with {package_publication_status} status in {package_series} {pocket}."
                )
                binary_build_link = binaries[0].build_link
                binary_build = launchpad.load(binary_build_link)
                build_found = True
                changesfile_url = binary_build.changesfile_url
                buildinfo_url = binary_build.buildinfo_url
                buildinfo_remote_filename = buildinfo_url.split("/")[-1]
                buildlog_url = binary_build.build_log_url
                changesfile_resp = launchpad._browser.get(changesfile_url).decode("utf-8", errors="ignore")
                buildinfo_resp = launchpad._browser.get(buildinfo_url).decode("utf-8", errors="ignore")
                buildlog_resp = launchpad._browser.get(buildlog_url).decode("utf-8", errors="ignore")

                # write the changes to file named
                # {package_name}_{package_version}_{package_architecture}_{package_series}.changes
                changes_filename = f"{package_name}_{package_version}_{package_architecture}_{package_series}.changes"
                with open(
                    changes_filename, "w"
                ) as f:
                    f.write(changesfile_resp)
                    print(
                        f"INFO: \tchanges written to "
                        f"{changes_filename}"
                    )

                # write the build info to file named
                # {package_name}_{package_version}_{package_architecture}_{package_series}.buildinfo
                buildinfo_filename = f"{package_name}_{package_version}_{package_architecture}_{package_series}.buildinfo"
                with open(
                    buildinfo_filename, "w"
                ) as f:
                    f.write(buildinfo_resp)
                    print(
                        f"INFO: \tbuildinfo written to "
                        f"{buildinfo_filename}"
                    )

                # write the build log to file named
                # {package_name}_{package_version}_{package_architecture}_{package_series}.buildlog
                buildlog_filename = f"{package_name}_{package_version}_{package_architecture}_{package_series}.buildlog"
                with open(
                    buildlog_filename, "w"
                ) as f:
                    f.write(buildlog_resp)
                    print(
                        f"INFO: \tbuildlog written to "
                        f"{buildlog_filename}"
                    )

                # find the hashes of buildinfo_filename in the changesfile_resp and verify that they match hash
                # of the buildinfo_filename file already written to disk
                sha256_checksums_found = False
                for changesfile_line in changesfile_resp.splitlines():
                    if "Checksums-Sha256:" in changesfile_line:
                        sha256_checksums_found = True
                    if sha256_checksums_found and buildinfo_remote_filename in changesfile_line:
                        # get the hash from the changesfile_line
                        changesfile_buildinfo_hash = changesfile_line.split()[0]
                        # get the hash of the buildinfo content and compare it to the hash in the changes file
                        sha256hash = hashlib.sha256(buildinfo_resp.encode("UTF-8")).hexdigest()
                        if changesfile_buildinfo_hash == sha256hash:
                            print(f"INFO: \tHash of {buildinfo_remote_filename} matches hash in changes file.")
                        else:
                            print(f"**********ERROR: \tHash of {buildinfo_remote_filename} does not match hash in changes file.")
                        # we have found the hash of the buildinfo_filename in the changes file so we can stop
                        # iterating over the changesfile lines
                        break
            else:
                print(
                    f"INFO: \tNo {package_publication_status} binaries found for {package_name}  {package_architecture} version {package_version} in {package_series} {pocket}"
                )
            if build_found:
                # if we have found the binary package we can stop iterating over the publication statuses
                break
        if build_found:
            # if we have found the source package we can stop iterating over the pockets
            break
    if not build_found:
        print(
            f"**********ERROR: \tNo Published or Superseded binaries found for {package_name} {package_architecture} version {package_version} in {package_series} any {ARCHIVE_POCKETS} pocket."
        )

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
    "version in the archive. We use this in our Launchpad "
    'query to query either "source" package or "amd64" package '
    'version. Using "amd64" will query the version of the '
    'binary package. "source" is a valid value for '
    "architecture with Launchpad and will query the version of "
    "the source package. The default is amd64. ",
    required=True,
    default="amd64",
    show_default=True,
)
@click.option(
    "--ppa",
    "ppas",
    required=False,
    multiple=True,
    type=click.STRING,
    help="Additional PPAs that you wish to query for package version status."
    "Expected format is "
    "ppa:'%LAUNCHPAD_USERNAME%/%PPA_NAME%' eg. ppa:philroche/cloud-init"
    "Multiple --ppa options can be specified",
    default=[],
)
@click.option(
    "--launchpad-user",
    "lp_user",
    required=False,
    type=click.STRING,
    help="Launchpad username to use when querying PPAs. This is important id "
    "you are querying PPAs that are not public.",
    default=None,
)
@click.pass_context
def ubuntu_package_buildinfo(
    ctx, series, package_name, package_version, logging_level, package_architecture, ppas, lp_user
):
    # type: (Dict, Text, Text,Text, Text, Optional[Text], Text) -> None
    """
    Watch specified packages in the ubuntu archive for transition between
    archive pockets/PPAs. Useful when waiting for a package update to be published.
    """

    # We log to stderr so that a shell calling this will not have logging
    # output in the $() capture.
    level = logging.getLevelName(logging_level)
    logging.basicConfig(level=level, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")

    get_buildinfo(series, package_name, package_version, package_architecture, list(ppas), lp_user)


if __name__ == "__main__":
    ubuntu_package_buildinfo(obj={})
