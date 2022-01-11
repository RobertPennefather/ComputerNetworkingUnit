Project by:
Robert Pennefather - 21511164
Lukas Pfeifle - 21493735

To compile the server use:
java -Djavax.net.ssl.keyStore=mySrvKeystore -Djavax.net.ssl.keyStorePassword=123456 Server -h host:port

to compile the client use:
java -Djavax.net.ssl.trustStore=clientNStore -Djavax.net.ssl.trustStorePassword=123456 Client -h host:port -u certificate
*these two arguments are required to connect to the server and identify the client 
*where N in clientNstore is the number of the client

Summary:
Each client has its own folder which represents the host itself. The folders contain files to upload, certificate of the client, keystore of the client as well as the client code and class, which must be compiled for each client. 

The server folder has the server certificate, server keystore, server code and class as well as an oldtrusty folder to handle the requests of each client. Each circle folder represents a circle of trust, and places the client in the correct folder. Within a certain circle folder the following files can be found, client certificates belonging to the circle, files that have been uploaded by anyone of the clients and a trust.txt which holds the names of the files that have been trusted by the circle it is located in. This trust file cannot be modified in anyway as a security measure. 

We were short on time, and were only able to write the server and client code in Java, rather than in two languages. We did try to get a C based client to work but had no success because ssl was not working on mac at the time. Python was constantly giving us errors about not having the correct cipher suites and would not allow an ssl connection. Due to these issues and the time constraint we thought that it would be more beneficial to have a running file system rather than spending any more time trying to get code to work in either C or Python.

References:

Used as a guide to create certificates and sign them:
https://gist.github.com/mtigas/952344

Used as guide to create keystores, and add certificates/keys to them:
http://stackoverflow.com/questions/4022604/java-how-to-obtain-keystore-file-for-a-certification-crt-file

Client and Server communication using ssl / C++ :
http://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works

Used for file transferring between client/server:http://www.rgagnon.com/javadetails/java-0542.html Used for sending basic messages to client/server:http://stackoverflow.com/questions/1776457/java-client-server-application-with-sockets Listing files recursively:http://stackoverflow.com/questions/2056221/recursively-list-files-in-java SSL connection:http://docs.oracle.com/javase/1.5.0/docs/guide/security/jsse/samples/index.html Creating keyStore and using them:http://stilius.net/java/java_ssl.php

OpenSSL Basics:
https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs