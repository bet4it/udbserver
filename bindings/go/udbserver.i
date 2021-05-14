// without it, you get the raw int32_t, uint64_t, etc types
// which are actually quite hard to deal with
%include "stdint.i"

%rename("%(lowercamelcase)s") "";
// %rename("NewFoo") "foo_new";

%module udbserver
%{
#include "udbserver.h"
%}

%include "udbserver.h"
