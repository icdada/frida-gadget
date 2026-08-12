"""Directories the package reads and writes."""
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
FILE_DIR = ROOT_DIR.joinpath("files")
