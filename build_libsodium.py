"""Build the crypt4gh.sodium extension against the bundled or the system-wide libsodium.

setuptools loads this module through [tool.setuptools.cmdclass] in pyproject.toml.
"""

import os
import subprocess
import sys
from pathlib import Path

from setuptools.command.build_ext import build_ext

_here = Path(__file__).resolve().parent

# Check for SODIUM_INSTALL environment variable
use_system_sodium = os.environ.get('SODIUM_INSTALL') == 'system'

# Path to libsodium
LIBSODIUM = _here / 'libsodium-stable'
# Path to the built libsodium library
LIBSODIUM_BUILD = _here / 'libsodium-build'

if sys.platform == "darwin":
    extra_compile_args = ['-fPIC','-dead_strip']
    extra_link_args = ['-fPIC','-dead_strip', '-Xlinker', '-dead_strip_dylibs']
else:
    extra_compile_args = ['-fPIC', '-ffunction-sections', '-fdata-sections']
    extra_link_args = ['-fPIC', '-Wl,--as-needed', '-Wl,--gc-sections']
    # on linux, gc-sections is too conservative and keeps more than needed
    # the final C-extension will likely be bigger than needed: ¯\_(ツ)_/¯
    # On macos, the linker is more aggressive and makes a smaller shared object

class BuildLibsodium(build_ext):
    def run(self):

        if use_system_sodium:
            print('''\
Skipping build, using system-installed libsodium.
CFLAGS and LDFLAGS may be needed.
''')
            return super().run()

        print("Bundling libsodium from libsodium-stable.")
        # Configure and build libsodium
        cmd = ['./configure',
               '--prefix', str(LIBSODIUM_BUILD),
               '--enable-minimal',
               '--disable-shared',
               '--enable-static',
               '--enable-pic',
               ]
        if not (LIBSODIUM / 'config.status').exists():
            subprocess.check_call(cmd, cwd=LIBSODIUM)
        subprocess.check_call(['make'], cwd=LIBSODIUM)
        #subprocess.check_call(['make', 'check'], cwd=str(LIBSODIUM))

        # copy to LIBSODIUM_BUILD/{include,lib}
        # so it's easier to point the extension at it
        subprocess.check_call(['make', 'install'], cwd=LIBSODIUM)

        for ext in self.extensions:
            ext.include_dirs.append(str(LIBSODIUM_BUILD / 'include'))
            ext.library_dirs.append(str(LIBSODIUM_BUILD / 'lib'))
            ext.extra_compile_args.extend(extra_compile_args)
            ext.extra_link_args.extend(extra_link_args)

        super().run()
