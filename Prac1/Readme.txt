1) To compile both the client and server use

	make
	or 
	make main

	The compiled files will be stored in the Compiled subdirectory

2) To run the server
	
	from the main project directory:
	make runServer 
	
	To pass arguments to server, cd to the Compiled directory and use:
	./Server Argument1 Argument2 ...

	The arguments are structured as follows: setting=value
	The available settings are: cert, key and port
	
	cert specifies the path to the certificate of the server 
	key specifies the path to the private key of the server
	port specifies on what port the server should be run
	
	If a setting is not set, the following defaults apply:
		cert="../keys/webServCert.crt"
		key="../keys/webServ.key"
		port=5000

	The user can type EXIT at any time to stop the server and close the program.
	
	The files hosted by the server are kept in the Media_files folder. This folder is dynamically indexed every time the server is run, so a file can simply be added before the server is run to 	host the file on the server. 
	The index.html file is the home page for the server when accessed with a browser and should never be deleted. files_list.html is created when the program is executed and the files are indexed.

3) To run the client

	Please ensure that the server is running on the local machine before running the client, otherwise the client will simply say Connection refused and exit.
	
	from the main project directory:
	make runClient 
	
	To pass arguments to server, cd to the Compiled directory and use:
	./Client Argument1 Argument2 ...
	
	The arguments are structured as follows: setting=value
	The available settings are: CA and address
	
	CA specifies the path to the certificate of the CA that should be used to verify the server 
	address specifies the ip address and port of the server to connect to in the format ip_address:port
	
	If a setting is not set, the following defaults apply:
		CA="../keys/cert.crt"
		address=0.0.0.0:5000

4) Using the client

	The client will automatically request the list of files from the server and display it. The user will be prompted to enter the name of the file to be retrieved.
	Html files retrieved from the server will be displayed in the terminal in plaintext
	Other files will be downloaded and saved in the parent directory under the same name as is specified on the server.
	The user can type files_list.html at any time to retrieve the list of files on the server that can be downloaded by the client.
	The user can type EXIT at any time to close the client program.
