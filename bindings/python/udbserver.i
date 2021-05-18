// this is important to use any non int_t types
%include "stdint.i"

%typemap(in) uc_handle {
  PyObject* uch = PyObject_GetAttr($input, PyUnicode_FromString("_uch"));
  PyObject* v = PyObject_GetAttr(uch, PyUnicode_FromString("value"));
  $1 = (uc_handle)PyLong_AsVoidPtr(v);
}

%module udbserver
%{
#include "udbserver.h"
%}
%include "udbserver.h"
