rsakeygen: rsakeygen.c rsakeygen.h prac3.c prac3.h
	gcc rsakeygen.c prac3.c -lgmp -o rsakeygen
	./rsakeygen -bitLen 128 -fopub pubkey.txt -fopriv privkey.txt -init "Hello there, General Kenobi"

rsaencrypt: rsaencrypt.c rsaencrypt.h prac3.c prac3.h
	gcc rsaencrypt.c prac3.c -lgmp -o rsaencrypt
	./rsaencrypt -fo cipher.key -fopub pubkey.txt -key "Hello there, General Kenobi" 

rsadecrypt: rsadecrypt.c rsadecrypt.h prac3.c prac3.h
	gcc rsadecrypt.c prac3.c -lgmp -o rsadecrypt
	./rsadecrypt -fi cipher.key -fopriv privkey.txt -fo plain.txt

rc4encrypt: rc4.c rc4.h prac3.c prac3.h
	gcc rc4.c prac3.c -lgmp -o rc4
	./rc4 -fi "a.jpg" -fo "encrypted.enc"

rc4decrypt: rc4.c rc4.h prac3.c prac3.h
	gcc rc4.c prac3.c -lgmp -o rc4
	./rc4 -fi "encrypted.enc" -fo "b.jpg" -key "plain.txt"

clean:
	rm rsakeygen
	rm rsaencrypt
	rm rsadecrypt
	rm rc4


