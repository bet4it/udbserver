// this is important to use any non int_t types
%include "stdint.i"

%module udbserver
%{
#include "udbserver.h"
%}
%include "udbserver.h"
