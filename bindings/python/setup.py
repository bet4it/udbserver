import os
import sysconfig
from setuptools import setup
from setuptools_rust import Binding, RustExtension
from setuptools.command.build_ext import build_ext
from setuptools.command.bdist_wheel import bdist_wheel

class CustomBuildExt(build_ext):
    def get_ext_filename(self, ext_name):
        filename = super().get_ext_filename(ext_name)
        suffix = sysconfig.get_config_var('EXT_SUFFIX')
        ext = os.path.splitext(filename)[1]
        return filename.replace(suffix, '') + ext

class CustomBdistWheel(bdist_wheel):
    def get_tag(self):
        _, _, plat = super().get_tag()
        return ('py3', 'none', plat)

setup(
    name='udbserver',
    rust_extensions=[RustExtension('udbserver.libudbserver', binding=Binding.NoBinding, path='../../Cargo.toml', features=['capi'])],
    cmdclass={'build_ext': CustomBuildExt, 'bdist_wheel': CustomBdistWheel},
)
