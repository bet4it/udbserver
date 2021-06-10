#include <stdio.h>
#include <Python.h>

#include "udbserver.h"

static PyObject* _udbserver(PyObject *self, PyObject *args) {
    PyObject *uc;
    if (!PyArg_ParseTuple(args, "O", &uc)) {
        return NULL;
    }
    PyObject* uch = PyObject_GetAttr(uc, PyUnicode_FromString("_uch"));
    PyObject* v = PyObject_GetAttr(uch, PyUnicode_FromString("value"));
    void *p = PyLong_AsVoidPtr(v);
    udbserver(p);
    Py_RETURN_NONE;
}

static PyObject* _udbserver_hook(PyObject *self, PyObject *args) {
    PyObject *uc, *addr, *size, *data;
    if (!PyArg_ParseTuple(args, "OkkO", &uc, &addr, &size, &data)) {
        return NULL;
    }
    PyObject* uch = PyObject_GetAttr(uc, PyUnicode_FromString("_uch"));
    PyObject* v = PyObject_GetAttr(uch, PyUnicode_FromString("value"));
    void *p = PyLong_AsVoidPtr(v);
    udbserver(p);
    Py_RETURN_NONE;
}

static PyMethodDef udbserver_methods[] = { 
    {   
        "udbserver", _udbserver, METH_VARARGS,
        "Start udbserver."
    },  
    {   
        "udbserver_hook", _udbserver_hook, METH_VARARGS,
        "Udbserver Hook."
    },  
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef udbserver_definition = { 
    PyModuleDef_HEAD_INIT,
    "udbserver",
    "Unicorn debugger server.",
    -1, 
    udbserver_methods
};

PyMODINIT_FUNC PyInit_udbserver(void) {
    Py_Initialize();
    return PyModule_Create(&udbserver_definition);
}
