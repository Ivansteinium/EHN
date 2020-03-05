main: Server.c Server.h Client.h Client.c Compiled/Client Compiled/Server
	
Compiled/Server: Server.c Server.h
	gcc Server.c -o Compiled/Server -L/usr/local/ssl -lssl -lcrypto -pthread
	
Compiled/Client: Client.c Client.h
	gcc Client.c -o Compiled/Client -L/usr/local/ssl -lssl -lcrypto
	
runServer: Compiled/Server
	(cd Compiled && exec ./Server)

runClient: Compiled/Client
	(cd Compiled && exec ./Client)
	
clean:
	rm Compiled/Server
	rm Compiled/Client


