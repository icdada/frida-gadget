"""init file for scripts folder."""
import sys
import subprocess
from .logger import logger


def import_or_install(package):
    """Install a package, or exit asking the user to try again.

    Args:
        package (string): Name of the package to install.
    """
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'frida', '--user'])
        logger.info('Try Again')
        sys.exit(0)


import_or_install('frida')  # Install missing packages
INSTALLED_FRIDA_VERSION: str = __import__('frida').__version__  # Get installed frida version
