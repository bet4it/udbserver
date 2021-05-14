package udbserver

// Note that we link to librust_bining.* in standard system path
// -L${SRCDIR} in the following line would allow shipping with the .{so,dylib,dll}
// in the go directory and not in the system path (since we need it for python, I use /usr/local/lib here to standarize)

// #cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -ludbserver
import "C"
