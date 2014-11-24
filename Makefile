all:
	cc -fPIC -c tweetnacl.c -Os
	cc -fPIC -c LiteCrypto.c -Os
	ar rc libLiteCrypto.a tweetnacl.o LiteCrypto.o
	ranlib libLiteCrypto.a
LiteCrypto:
	cc -fPIC -c tweetnacl.c -Os
	cc -fPIC -c LiteCrypto.c -Os
	ar rc libLiteCrypto.a tweetnacl.o LiteCrypto.o
	ranlib libLiteCrypto.a
clean:
	rm libLiteCrypto.a tweetnacl.o LiteCrypto.o
