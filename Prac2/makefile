main: AES.c AES.h
	gcc AES.c -o Compiled/AES

cbc128e: main
	./Compiled/AES -e -cbc 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb128e: main
	./Compiled/AES -e -cfb 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cbc192e: main
	./Compiled/AES -e -cbc 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb192e: main
	./Compiled/AES -e -cfb 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cbc256e: main
	./Compiled/AES -e -cbc 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb256e: main
	./Compiled/AES -e -cfb 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cbc128d: main
	./Compiled/AES -d -cbc 128 -t "61B931E31408A00D22A768DCAC9DCE5C4C9E2A6D14209B1AD501E669821948A9" -key "Very strong password" -iv "Initialization vector"

cfb128d: main
	./Compiled/AES -d -cfb 128 -t "D8DABAD3A812506A1B264C938384EA125CC8E6FE467CF045CCDC3C" -key "Very strong password" -iv "Initialization vector"

cbc192d: main
	./Compiled/AES -d -cbc 192 -t "B2B16F524A853F715702534C329940CE646F88D14D9FAE47D8D27B5F18632609" -key "Very strong password" -iv "Initialization vector"

cfb192d: main
	./Compiled/AES -d -cfb 192 -t "E79C9EF26A12657FA6E2230E4CF5EE9C8D8DECA982B8FBD505F8BA" -key "Very strong password" -iv "Initialization vector"

cbc256d: main
	./Compiled/AES -d -cbc 256 -t "C5777ED6F9BAC2BBF1A1B4B2525A8A4E6F26AADD8412AF160E2ED97D331CB3E6" -key "Very strong password" -iv "Initialization vector"

cfb256d: main
	./Compiled/AES -d -cfb 256 -t "406CDEA06438A4653FAD7D3E7D249740A94F966899C0640BD67A9B" -key "Very strong password" -iv "Initialization vector"

clean:
	rm Compiled/AES


