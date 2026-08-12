"""init file for scripts folder."""

try:
    import frida

    INSTALLED_FRIDA_VERSION: str = frida.__version__
except ImportError:
    # frida is only read to work out which gadget release to download, so the
    # tool still works without it as long as --frida-version says which one.
    INSTALLED_FRIDA_VERSION: str = None
