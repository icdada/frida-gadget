"""Github module for download frida gadget library."""
# Base code is sourced from the GitHub repository of Objection.
# Source: https://github.com/sensepost/objection/blob/master/objection/utils/patchers/github.py
import lzma
import re
from pathlib import Path
import requests

class FridaGithub:
    """Interact with Github."""

    DEFAULT_GITHUB_API_BASE = 'https://api.github.com/repos/frida/frida'

    # 'owner/repo', or a github.com URL with an optional scheme, 'www.',
    # '.git' suffix and trailing slash. Any other host is rejected so a
    # typo cannot send the request somewhere unexpected.
    GITHUB_REPO_PATTERN = re.compile(
        r'^(?:(?:https?://)?(?:www\.)?github\.com/)?'
        r'(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/'
        r'(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$'
    )

    # the 'context' of this Github instance
    gadget_version = None
    github_api_base = None

    def __init__(self, gadget_version: str = "", github_repo: str = ""):
        """Init a new instance of Github."""
        if gadget_version:
            self.gadget_version = gadget_version

        self.github_api_base = self.parse_repo(github_repo)
        self.request_cache = {}

    @classmethod
    def parse_repo(cls, github_repo: str) -> str:
        """Turn a repository reference into a Github API base URL.

        :param github_repo: 'owner/repo' or a github.com URL, empty for frida/frida
        :return:
        """
        if not github_repo:
            return cls.DEFAULT_GITHUB_API_BASE

        match = cls.GITHUB_REPO_PATTERN.match(github_repo.strip())
        if not match:
            raise ValueError(
                'Invalid GitHub repository '
                f'(expected \'owner/repo\' or a github.com URL): {github_repo}')

        return f'https://api.github.com/repos/{match.group("owner")}/{match.group("repo")}'

    @property
    def latest_release_url(self) -> str:
        """Endpoint of the latest release of the selected repository.

        :return:
        """
        return f'{self.github_api_base}/releases/latest'

    @property
    def tagged_release_url(self) -> str:
        """Endpoint template of a tagged release of the selected repository.

        :return:
        """
        return f'{self.github_api_base}/releases/tags/{{tag}}'

    def _call(self, endpoint: str) -> dict:
        """Make a call to Github and cache the response.

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

    def get_latest_version(self) -> str:
        """Call Github and get the tag_name of the latest release.

        :return:
        """
        self.gadget_version = self._call(self.latest_release_url)['tag_name']

        return self.gadget_version

    def get_assets(self) -> dict:
        """Get the assets for the currently selected gadget_version.

        :return:
        """
        assets = self._call(self.tagged_release_url.format(tag=self.gadget_version))

        if 'assets' not in assets:
            raise FileNotFoundError(
                f'Unable to determine assets for gadget version \'{self.gadget_version}\'. '
                'Are you sure this version is available on Github?')

        return assets['assets']

    def download_asset(self, url: str, output_file: str) -> None:
        """Download an asset from Github.

        :param url:
        :param output_file:
        :return:
        """
        if not output_file.endswith('.xz'):
            raise ValueError(f'The asset must be downloaded to a .xz path, got {output_file!r}.')
        filepath = Path(output_file)
        if filepath.exists() and filepath.stat().st_size > 0:
            return

        response = requests.get(url, timeout=600, stream=True)
        with open(output_file, 'wb') as asset:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    asset.write(chunk)

    def download_gadget_so(self, url, gadget_fullpath: str) -> str:
        """Download the gadget library from Github.

        :param gadget_path:
        :return:
        """
        if not gadget_fullpath.endswith('.so'):
            raise ValueError(f'The gadget must be written to a .so path, got {gadget_fullpath!r}.')
        gadget_path = Path(gadget_fullpath)
        download_directory = gadget_path.parent
        if gadget_path.exists():
            return gadget_fullpath

        if not download_directory.exists():
            download_directory.mkdir(parents=True, exist_ok=True)

        xz_gadget_fullpath = gadget_fullpath + ".xz"
        self.download_asset(url, xz_gadget_fullpath)
        with lzma.open(xz_gadget_fullpath, "rb") as lzma_file:
            decompressed_data = lzma_file.read()

        with open(gadget_fullpath, "wb") as gadget_file:
            gadget_file.write(decompressed_data)

        return gadget_fullpath
