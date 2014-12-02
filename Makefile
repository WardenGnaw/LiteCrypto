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
driver: LiteCrypto driver.c
	gcc -Os driver.c libLiteCrypto.a -o driver
clean:
	rm libLiteCrypto.a tweetnacl.o LiteCrypto.o
