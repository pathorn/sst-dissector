OUT=sst.so
CXXSRC=packet-ssttcp.cpp packet-protobufs.cpp
CSRC=plugin.c

CFLAGS=-g -DWS_VAR_IMPORT=extern -DHAVE_STDARG_H -fPIC -DHAVE_VPRINTF -I/usr/include/wireshark $(shell pkg-config --cflags gmodule-2.0)
CXXFLAGS=$(CFLAGS)
LDFLAGS=-g -L/usr/lib/wireshark -lwireshark -shared -fPIC

OBJ=$(CXXSRC:.cpp=.o) $(CSRC:.c=.o)

$(OUT): $(OBJ)
	g++ $(OBJ) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(OUT)

install: $(OUT)
	install -t /usr/lib/wireshark/plugins -m 0755 $(OUT)

