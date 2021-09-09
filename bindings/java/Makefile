.PHONY: clean uninstall

JC=javac

JAVA_HOME := $(shell readlink -f `which $(JC)` | sed "s:/bin/javac::")

JAVA_INC := $(shell realpath $(JAVA_HOME)/include)

JAVA_PLATFORM_INC := $(shell dirname `find $(JAVA_INC) -name jni_md.h`)

UDBSERVER_INC=../../include

UNICORN_JAR ?= /usr/share/java/unicorn.jar

OS := $(shell uname)
ifeq ($(OS),Darwin)
   LIB_EXT=.dylib
else ifeq ($(OS),Linux)
   LIB_EXT=.so
else
   LIB_EXT=.dll
endif

CC=gcc
CFLAGS=-fPIC
LDFLAGS=-shared -fPIC
LIBS=-ludbserver
LIBDIR=-L../../target/release
INCS=-I$(JAVA_INC) -I$(JAVA_PLATFORM_INC) -I$(UDBSERVER_INC)

JFLAGS=-cp .:$(UNICORN_JAR)

HEADER=udbserver_Udbserver.h
OBJ=udbserver_Udbserver.o

JARFILE=udbserver.jar

all: lib jar

%.class: %.java
	$(JC) $(JFLAGS) $<

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCS) $< -o $@

$(HEADER): udbserver/Udbserver.java
	$(JC) $(JFLAGS) -h . $<

$(OBJ): udbserver_Udbserver.c $(HEADER)
	$(CC) -c $(CFLAGS) $(INCS) $< -o $@

libudbserver_java$(LIB_EXT): $(OBJ) $(HEADER)
	$(CC) -o $@ $(LDFLAGS) $(OBJ) $(LIBDIR) $(LIBS)

lib: libudbserver_java$(LIB_EXT)

$(JARFILE) : udbserver/Udbserver.class
	jar cf $(JARFILE) $<

jar: $(JARFILE)

example: Example.class lib jar
	java $(JFLAGS) Example

install: lib jar
	cp libudbserver_java$(LIB_EXT) /usr/lib
	cp $(JARFILE) /usr/share/java

uninstall:
	rm -f /usr/lib/libudbserver_java$(LIB_EXT)
	rm -f /usr/share/java/$(JARFILE)

clean:
	rm -f udbserver/*.class
	rm -f *.o
	rm -f *.h
	rm -f *.so
	rm -f *.dylib
	rm -f *.dll
	rm -f *.class
	rm -f *.jar
