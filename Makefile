all: testDriver
testDriver: libLiteCrypto.a testDriver.c
	cc -Os testDriver.c libLiteCrypto.a -o testDriver
libLiteCrypto.a: tweetnacl.c LiteCrypto.c
	cc -fPIC -c tweetnacl.c -Os
	cc -fPIC -c LiteCrypto.c -Os
	ar rc libLiteCrypto.a tweetnacl.o LiteCrypto.o
	ranlib libLiteCrypto.a
%.c: %.h
	touch $@
clean:
	rm libLiteCrypto.a tweetnacl.o LiteCrypto.o testDriver
