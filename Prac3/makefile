rc4: rc4.c rc4.h prac3.c prac3.h
	gcc rc4.c prac3.c -lgmp -o rc4

rsakeygen: rsakeygen.c rsakeygen.h prac3.c prac3.h
	gcc rsakeygen.c prac3.c -lgmp -o rsakeygen

rsaencrypt: rsaencrypt.c rsaencrypt.h prac3.c prac3.h
	gcc rsaencrypt.c prac3.c -lgmp -o rsaencrypt

rsadecrypt: rsadecrypt.c rsadecrypt.h prac3.c prac3.h
	gcc rsadecrypt.c prac3.c -lgmp -o rsadecrypt

demo: rc4 rsakeygen rsaencrypt rsadecrypt
	touch input.txt
	echo "If you can see this in output.txt, the software is working correctly." > input.txt
	./rc4 -fi "input.txt" -fo "encrypted.enc"
	./rsakeygen -bitLen 1024 -fopub pubkey.txt -fopriv privkey.txt -init "RNG seed"
	./rsaencrypt -fo cipher.key -fopub pubkey.txt -key "EHN prac 3 demo"
	./rsadecrypt -fi cipher.key -fopriv privkey.txt -fo plain.txt
	./rc4 -fi "encrypted.enc" -fo "output.txt" -key "plain.txt"
	cat output.txt

clean:
	rm rsakeygen
	rm rsaencrypt
	rm rsadecrypt
	rm rc4
	rm cipher.key
	rm encrypted.enc
	rm input.txt
	rm output.txt
	rm plain.txt
	rm privkey.txt
	rm pubkey.txt


