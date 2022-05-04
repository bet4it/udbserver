#!/bin/bash
set -e -x

cd bindings/python

# Compile wheels
if [ -f /opt/python/cp36-cp36m/bin/python ];then
  /opt/python/cp36-cp36m/bin/python setup.py bdist_wheel
else
  python3 setup.py bdist_wheel
fi
cd dist
python3 -m pip install --user auditwheel
python3 ../auditwheel repair *.whl
mv -f wheelhouse/*.whl .
