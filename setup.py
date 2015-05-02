import sys
# import glob
# import os
# import shutil
import hash_check
from cx_Freeze import setup, Executable
# from PyQt4 import QtCore
 
# app = QtCore.QCoreApplication(sys.argv)
# qt_library_path = QtCore.QCoreApplication.libraryPaths()

# imageformats_path = None
# for path in qt_library_path:
    # if os.path.exists(os.path.join(path, 'imageformats')):
        # imageformats_path = os.path.join(path, 'imageformats')
        # local_imageformats_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imageformats')
        # if not os.path.exists(local_imageformats_path):
            # os.mkdir(local_imageformats_path)
        # for file in glob.glob(os.path.join(imageformats_path, '*')):
            # shutil.copy(file, os.path.join(local_imageformats_path, os.path.basename(file)))

# Dependencies are automatically detected, but it might need fine tuning.
includefiles = ['hash_check.ui']
#includes = ['sip', 'PyQt4.QtCore']
build_exe_options = {"icon": "icons/logo.ico", 'include_files': includefiles}
#build_exe_options = {"icon": "icons/logo.ico", 'include_files': includefiles, 'includes':includes}

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