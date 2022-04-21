#include <stdio.h>
#include <Python.h>

#include <udbserver.h>

static PyObject* _udbserver(PyObject *self, PyObject *args) {
    PyObject *uc;
    unsigned short port = 1234;
    unsigned long start_addr = 0;
    if (!PyArg_ParseTuple(args, "O|HK", &uc, &port, &start_addr)) {
        return NULL;
    }
    PyObject* uch = PyObject_GetAttr(uc, PyUnicode_FromString("_uch"));
    PyObject* v = PyObject_GetAttr(uch, PyUnicode_FromString("value"));
    void *p = PyLong_AsVoidPtr(v);
    udbserver(p, port, start_addr);
    Py_RETURN_NONE;
}

static PyMethodDef udbserver_methods[] = { 
    {   
        "udbserver", _udbserver, METH_VARARGS,
        "Start udbserver."
    },  
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef udbserver_definition = { 
    PyModuleDef_HEAD_INIT,
    "udbserver",
    "Unicorn emulator debug server.",
    -1, 
    udbserver_methods
};

PyMODINIT_FUNC PyInit_udbserver(void) {
    Py_Initialize();
    return PyModule_Create(&udbserver_definition);
}
