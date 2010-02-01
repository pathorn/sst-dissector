OUT=sst.so
CXXSRC=packet-ssttcp.cpp packet-protobufs.cpp
CSRC=plugin.c

# ar -p wireshark-dev_1.0.2-3+lenny5_i386.deb data.tar.gz | tar -zxvf -

CFLAGS=-g -DWS_VAR_IMPORT=extern -DHAVE_STDARG_H -fPIC -DHAVE_VPRINTF -I./usr/include/wireshark -I/usr/include/wireshark $(shell pkg-config --cflags gmodule-2.0)
CXXFLAGS=$(CFLAGS)
LDFLAGS=-g -L/Applications/Wireshark.app/Contents/Resources/lib -L/usr/lib/wireshark -lwireshark -shared -dynamiclib -fPIC

OBJ=$(CXXSRC:.cpp=.o) $(CSRC:.c=.o)

$(OUT): $(OBJ)
	g++ $(OBJ) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(OUT)

install: $(OUT)
	if [ x"`uname`" = x"Darwin" ]; then \
		install -m 0755 $(OUT) /Applications/Wireshark.app/Contents/Resources/lib/wireshark/plugins/; \
	else \
		install -t /usr/lib/wireshark/plugins -m 0755 $(OUT) ;\
	fi

