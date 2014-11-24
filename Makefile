all:
	cc -fPIC -c tweetnacl.c
	cc -fPIC -c LiteCrypto.c
	ar rc libLiteCrypto.a tweetnacl.o LiteCrypto.o
	ranlib libLiteCrypto.a
LiteCrypto:
	cc -fPIC -c tweetnacl.c
	cc -fPIC -c LiteCrypto.c
	ar rc libLiteCrypto.a tweetnacl.o LiteCrypto.o
	ranlib libLiteCrypto.a
clean:
	rm libLiteCrypto.a tweetnacl.o LiteCrypto.o
