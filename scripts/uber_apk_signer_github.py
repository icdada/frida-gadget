"""Github module for download frida gadget library."""
# Base code is sourced from the GitHub repository of Objection.
# Source: https://github.com/sensepost/objection/blob/master/objection/utils/patchers/github.py
from pathlib import Path
import hashlib
import os
import requests

class UberApkSignerGithub:
    """Interact with Github."""

    GITHUB_TAGGED_RELEASE = (
        'https://api.github.com/repos/patrickfav/uber-apk-signer/releases/tags/v{tag}'
    )

    # The signer is downloaded and then executed, so the release it comes from is
    # pinned rather than resolved to whatever is newest. SIGNER_SHA256 is the hash
    # the release publishes in checksum-sha256.txt, recorded here so a replaced
    # release is rejected instead of trusted because it ships a matching checksum.
    DEFAULT_SIGNER_VERSION = '1.3.0'
    KNOWN_SIGNER_SHA256 = {
        '1.3.0': 'e1299fd6fcf4da527dd53735b56127e8ea922a321128123b9c32d619bba1d835',
    }

    # the 'context' of this Github instance
    signer_version = None

    def __init__(self, signer_version: str = None):
        """Init a new instance of Github."""
        self.signer_version = signer_version or self.DEFAULT_SIGNER_VERSION
        self.request_cache = {}

    def _call(self, endpoint: str) -> dict:
        """
        Make a call to Github and cache the response.

        :param endpoint:
        :return:
        """
        # return a cached response if possible
        if endpoint in self.request_cache:
            return self.request_cache[endpoint]

        # get a new response
        results = requests.get(endpoint, timeout=30).json()

        # cache it
        self.request_cache[endpoint] = results

        # and return it
        return results

    def get_assets(self) -> dict:
        """
        Get the assets for the currently selected signer_version.

        :return:
        """
        assets = self._call(self.GITHUB_TAGGED_RELEASE.format(tag=self.signer_version))

        if 'assets' not in assets:
            raise FileNotFoundError(
                f'Unable to determine assets for signer version \'{self.signer_version}\'. '
                'Are you sure this version is available on Github?')

        return assets['assets']

    def download_asset(self, url: str, output_file: str) -> None:
        """
        Download an asset from Github.

        :param url:
        :param output_file:
        :return:
        """
        filepath = Path(output_file)
        if filepath.exists() and filepath.stat().st_size > 0:
            return

        response = requests.get(url, timeout=600, stream=True)
        with open(output_file, 'wb') as asset:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    asset.write(chunk)

    def download_signer_jar(self, assets: list, signer_fullpath: str) -> str:
        """
        Download the signer jar library from Github.

        :param assets:
        :param signer_path:
        :return:
        """
        if len(assets) != 2:
            raise ValueError('Unable to determine the correct asset to download.')
        if not signer_fullpath.endswith('.jar'):
            raise ValueError('Signer path must end with .jar')

        checksum_download_url = assets[0]['browser_download_url']
        uber_apk_signer_download_url = assets[1]['browser_download_url']
        if assets[1]['name'] == 'checksum-sha256.txt':
            checksum_download_url, uber_apk_signer_download_url = \
                uber_apk_signer_download_url, checksum_download_url
        if not uber_apk_signer_download_url.endswith('.jar'):
            raise ValueError('Download URL must end with .jar')

        signer_path = Path(signer_fullpath)
        download_directory = signer_path.parent
        if signer_path.exists():
            return signer_fullpath

        if not download_directory.exists():
            download_directory.mkdir(parents=True, exist_ok=True)

        check_sum_fullpath = signer_fullpath[:-4] + '.sha256'
        self.download_asset(checksum_download_url, check_sum_fullpath)

        with open(check_sum_fullpath, 'rb') as checksum_file:
            checksum = checksum_file.read(64).decode('utf-8')

        self.download_asset(uber_apk_signer_download_url, signer_fullpath)
        with open(signer_fullpath, 'rb') as signer_file:
            signer_data = signer_file.read()
            signer_hash = hashlib.sha256(signer_data).hexdigest()

        expected = self.KNOWN_SIGNER_SHA256.get(self.signer_version, checksum)
        if signer_hash not in (checksum, expected) or checksum != expected:
            os.remove(signer_fullpath)
            os.remove(check_sum_fullpath)
            raise ValueError(
                f'uber-apk-signer {self.signer_version} does not match the expected '
                f'sha256 {expected}, got {signer_hash}.')

        return signer_fullpath
