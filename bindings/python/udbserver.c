#include <stdio.h>
#include <stdint.h>
#include <Python.h>
#include <udbserver.h>

static PyObject* _udbserver(PyObject *self, PyObject *args) {
    PyObject *obj;
    void* uc;
    uint16_t port = 1234;
    uint64_t start_addr = 0;
    if (!PyArg_ParseTuple(args, "OHK", &obj, &port, &start_addr)) {
        return NULL;
    }
    uc = PyLong_AsVoidPtr(obj);
    udbserver(uc, port, start_addr);
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

PyMODINIT_FUNC PyInit_udbserver_rust(void) {
    Py_Initialize();
    
    return PyModule_Create(&udbserver_definition);
}
