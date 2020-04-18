main: AES.c AES.h
	gcc AES.c -o Compiled/AES

test:
	./Compiled/AES

cbc128e:
	./Compiled/AES -e -cbc 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb128e8:
	./Compiled/AES -e -cfb 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb128e64:
	./Compiled/AES -e -cfb 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb128e128:
	./Compiled/AES -e -cfb 128 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 128

cbc192e:
	./Compiled/AES -e -cbc 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb192e8:
	./Compiled/AES -e -cfb 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb192e64:
	./Compiled/AES -e -cfb 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb192e128:
	./Compiled/AES -e -cfb 192 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 128

cbc256e:
	./Compiled/AES -e -cbc 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector"

cfb256e8:
	./Compiled/AES -e -cfb 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb256e64:
	./Compiled/AES -e -cfb 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb256e128:
	./Compiled/AES -e -cfb 256 -t "Lorem ipsum dolor sit amet." -key "Very strong password" -iv "Initialization vector" -streamlen 128

cbc128d:
	./Compiled/AES -d -cbc 128 -t "61B931E31408A00D22A768DCAC9DCE5C4C9E2A6D14209B1AD501E669821948A9" -key "Very strong password" -iv "Initialization vector"

cfb128d8:
	./Compiled/AES -d -cfb 128 -t "D8DABAD3A812506A1B264C938384EA125CC8E6FE467CF045CCDC3C" -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb128d64:
	./Compiled/AES -d -cfb 128 -t "D86FD9D90B7643232E7F49D380FF9048AA35F3D384C81BFE12F4A451A9F5C159" -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb128d128:
	./Compiled/AES -d -cfb 128 -t "D86FD9D90B76432347A6E7DCE7D4A82E8F6C519328D7EBD9EEDA1ADBE7008705" -key "Very strong password" -iv "Initialization vector" -streamlen 128

cbc192d:
	./Compiled/AES -d -cbc 192 -t "B2B16F524A853F715702534C329940CE646F88D14D9FAE47D8D27B5F18632609" -key "Very strong password" -iv "Initialization vector"

cfb192d8:
	./Compiled/AES -d -cfb 192 -t "E79C9EF26A12657FA6E2230E4CF5EE9C8D8DECA982B8FBD505F8BA" -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb192d64:
	./Compiled/AES -d -cfb 192 -t "E72F2DAB2DC25D35EF6D823714BAA9282863F0FD9CE628F33AFC68164AE72D92" -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb192d128:
	./Compiled/AES -d -cfb 192 -t "E72F2DAB2DC25D35BBCE04FA8914BCB5B2990C3F6FB5C56DC32DE8D4E91FBE03" -key "Very strong password" -iv "Initialization vector" -streamlen 128

cbc256d:
	./Compiled/AES -d -cbc 256 -t "C5777ED6F9BAC2BBF1A1B4B2525A8A4E6F26AADD8412AF160E2ED97D331CB3E6" -key "Very strong password" -iv "Initialization vector"

cfb256d8:
	./Compiled/AES -d -cfb 256 -t "406CDEA06438A4653FAD7D3E7D249740A94F966899C0640BD67A9B" -key "Very strong password" -iv "Initialization vector" -streamlen 8

cfb256d64:
	./Compiled/AES -d -cfb 256 -t "403DB924F4316FA232D521805B100F059FB5FD1937377145C0356980ED752421" -key "Very strong password" -iv "Initialization vector" -streamlen 64

cfb256d128:
	./Compiled/AES -d -cfb 256 -t "403DB924F4316FA2D92104FB6F451F1602C2228240F4581A94591A61729A3931" -key "Very strong password" -iv "Initialization vector" -streamlen 128

clean:
	rm Compiled/AES


