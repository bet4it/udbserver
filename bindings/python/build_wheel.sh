#!/bin/bash
set -e -x

cd bindings/python

# Install cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
sudo yum install openssl-devel.x86_64 -y
cargo install cargo-c

# Install unicorn globally
rm -rf unicorn
git clone -b dev https://github.com/unicorn-engine/unicorn unicorn
cd unicorn
mkdir build_dylib
cd build_dylib
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
sudo make install
sudo ldconfig
cd ../..

# Compile wheels
cargo clean
export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/usr/local/lib64/pkgconfig
if [ -f /opt/python/cp36-cp36m/bin/python ];then
  /opt/python/cp36-cp36m/bin/python setup.py bdist_wheel
else
  python3 setup.py bdist_wheel
fi

cd dist
python3 -m pip install --user auditwheel
python3 ../auditwheel repair *.whl
mv -f wheelhouse/*.whl .
