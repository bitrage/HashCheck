import sys
# import glob
# import os
# import shutil
import hash_check
from cx_Freeze import setup, Executable


# Dependencies are automatically detected, but it might need fine tuning.
includefiles = ['hash_check.ui']
build_exe_options = {"icon": "icons/logo.ico", 'include_files': includefiles}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(  name = "Hash Check",
        version = hash_check.__version__,
        description = "Hash Check",
        options = {"build_exe": build_exe_options},
        executables = [Executable("hash_check.py", base=base)])