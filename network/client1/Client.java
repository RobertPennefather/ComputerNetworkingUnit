//CITS 3002 Project by:
//Robert Pennefather - 21511164
//Lukas Pfeifle - 21493735

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

public class Client {
    
    static SSLSocket sock = null;
    static SSLSocketFactory sslsocketfactory = null;
    
    static FileInputStream fis = null;
    static BufferedInputStream bis = null;
    static InputStream is = null;
    static ObjectInputStream in = null;
    
    static OutputStream os = null;
    static ObjectOutputStream out = null;
    
    static String host = null;
    static int port = -1;
    static String certificate = null;
    static Client client;
    static int clientNum;
    
    Client(){}
    
    public final static int FILE_SIZE = 3145729; //3MB
    static int timeout = 0;
    
    //Attempting to add file to oldtrusty by sending byte array through socket
    void addFile(String fileName) {
        
        try {
            
            String workingDirectory = System.getProperty("user.dir");
            File myFile = new File (workingDirectory, fileName);
            if(myFile.exists() && !myFile.isDirectory()) {
                
                //Find file size
                byte [] mybytearray  = new byte [(int)myFile.length()];
                if( mybytearray.length > FILE_SIZE){
                    System.out.println("File: '" + fileName + "' is too large, try to compress to 3MB");
                    System.exit(-1);
                } else {
                    
                    // send file name
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject(fileName);
                    out.flush();
                    
                    //confirmation of access
                    in = new ObjectInputStream(sock.getInputStream());
                    String access = (String)in.readObject();
                    
                    if (access.equals("no")){
                        System.out.println("File exists already, you don't have access to edit it. Please change file name");
                        return;
                    }
                    
                    //send file
                    fis = new FileInputStream(myFile);
                    bis = new BufferedInputStream(fis);
                    bis.read(mybytearray,0,mybytearray.length);
                    os = sock.getOutputStream();
                    
                    System.out.println("Sending " + fileName + "(" + mybytearray.length + " bytes)");
                    os.write(mybytearray,0,mybytearray.length);
                    os.flush();
                    System.out.println("Done.");
                }
            }
            else {
                
                // send error message
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("ERROR");
                out.flush();
                
                System.out.println("File: '" + fileName + "' is not in working directory");
                System.exit(-1);
            }
            
        } catch(ClassNotFoundException classnot){
            System.err.println("Data received in unknown format");
            System.exit(-1);
        } catch (NegativeArraySizeException ex) {
            
            try {
                // send error message
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("ERROR");
                out.flush();
                System.out.println("File: '" + fileName + "' is too large, try to compress to 3MB");
                System.exit(-1);
            } catch (IOException e) {
                System.out.println(e.getMessage());
                System.exit(-1);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        } finally {
            try {
                if (bis != null) bis.close();
                if (os != null) os.close();
            } catch (IOException e){
                System.out.println(e.getMessage());
            }
        }
    }
    
    void addCert(String certName) {
    
        try {
            in = new ObjectInputStream(sock.getInputStream());
            String exists = (String)in.readObject();
            
            String workingDirectory = System.getProperty("user.dir");
            File myCert = new File (workingDirectory, certName);
            
            if(myCert.exists() && !myCert.isDirectory()
               && (certName.endsWith(".crt") || certName.endsWith(".cer"))) {
                
                if (exists.equals("notExist")){
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject("");
                    out.flush();
                    
                    client.addFile(certName);
                }
                else if (exists.equals("exist")) {
                    System.out.println("Certificate is on server");
                }
                else {
                    System.out.println("ERROR: Wrong input received");
                    System.exit(-1);
                }
            }
            else {
                
                if (exists.equals("notExist")){
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject("ERROR");
                    out.flush();
                }
                
                // send error message
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("");
                out.flush();
                
                System.out.println("Certificate: '" + certName + "' is not in working directory");
                System.exit(-1);
            }
        } catch (ClassNotFoundException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }
    
    void fetchFile(String fileName, int circleLength, String certName) {
        
        try {
            int bytesRead;
            int current = 0;
            
            // send parameters
            ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(fileName);
            out.flush();
            out.writeObject(circleLength);
            out.flush();
            out.writeObject(certName);
            out.flush();
            
            //check file is there
            String exists = null;
            in = new ObjectInputStream(sock.getInputStream());
            exists = (String)in.readObject();
            
            if( exists.equals("ERROR")){
                System.out.println("File doesn't exist");
                System.exit(-1);
                
            } else if (exists.equals("c")) {
                System.out.println("File isn't trusted by " + circleLength + " people");
                System.exit(-1);
                
            } else if (exists.equals("n")) {
                System.out.println("File isn't trusted by " + certName);
                System.exit(-1);
                
            } else {
                // recieve file
                byte [] mybytearray  = new byte [FILE_SIZE];
                is = sock.getInputStream();
                bytesRead = is.read(mybytearray,0,mybytearray.length);
                current = bytesRead;
                
                do {
                    bytesRead =
                    is.read(mybytearray, current, (mybytearray.length-current));
                    if(bytesRead >= 0) current += bytesRead;
                } while(bytesRead > -1);
                
                System.out.write(mybytearray, 0 , current);
                System.out.println();
            }
            
        } catch(ClassNotFoundException classnot){
            System.err.println("Data received in unknown format");
        } catch (IOException e) {
            System.out.println("File couldn't be retrieved");
            System.exit(-1);
        } finally {
            if (is != null){ is = null;}
        }
    }
    
    void findIP( String hostnamePort) {
        
        String[] parts = hostnamePort.split(":");
        
        if ( host.equals(parts[0]) && port == Integer.parseInt(parts[1])){
            //String remoteAddress = host;
            String remoteAddress = sock.getInetAddress().toString();
            System.out.println(remoteAddress);
        }
        else {
            System.out.println("Not the oldtrusty server");
        }
    }
    
    void listFiles() {
        
        try {
            in = new ObjectInputStream(sock.getInputStream());
            String fileList = (String)in.readObject();
            System.out.println(fileList);
            
        } catch(ClassNotFoundException classnot){
            System.err.println("ERROR: Data received in unknown format");
            
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }
    
    void vouchFile(String fileName, String certName) {
        
        try {
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(fileName);
            out.flush();
            
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(certName);
            out.flush();
            
            in = new ObjectInputStream(sock.getInputStream());
            String exists = (String)in.readObject();
            
            if (exists.equals("exist")){
                System.out.println("Certificate '" + certName + "' now vouches for '" + fileName + "'");
            } else if (exists.equals("notExist")) {
                System.out.println("File/Certificate is not on server");
                System.exit(-1);
            }
            else {
                System.out.println("ERROR: Wrong input received");
                System.exit(-1);
            }
        } catch (ClassNotFoundException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    
    public static void main (String [] args ) throws IOException {
        
        client = new Client();
        clientNum = (int )(Math.random() * 10000);
        
        if (args.length < 4  || !args[0].equals("-h") || !args[2].equals("-u")) {
            System.out.println("USAGE: java Client -h hostname:port -u certificate");
            System.exit(-1);
        }
        
        try {
            
            String[] parts = args[1].split(":");
            host = parts[0];
            port = Integer.parseInt(parts[1]);
            certificate = args[3];
            
            sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            sock = (SSLSocket) sslsocketfactory.createSocket(host, port);

            System.out.println("Connecting...");
            
            client.findIP(args[1]);
            System.out.println();
            
            // send certificate name to server
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(certificate);
            out.flush();
            
            //send client number to server
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(clientNum);
            out.flush();
            
            client.addCert(certificate);
            
        } catch (IllegalArgumentException e) {
            System.out.println("USAGE: java Client -h hostname:port -u certificate");
            System.exit(-1);
            
        } catch (IOException e) {
            System.out.println("Could not connect to server");
            System.exit(-1);
        }
        
        try {
            
            int client_count = 0;
            
            for(int i=4; i < args.length; i++){
                
                System.out.println();
                
                //System.out.println(sock);
                
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject(clientNum + args[i]);
                out.flush();
                client_count++;
                
                String command = args[i];
            
                    if (command.equals("-a")) {
                        if (i == args.length-1){
                            System.out.println("USAGE: -a filename");
                            System.exit(-1);
                        }
                        else if ( args[++i].contains("trust")){
                            System.out.println("File won't upload, please rename without 'trust'");
                            System.exit(-1);
                        }
                        else {
                            client.addFile( args[i]);
                        }
                    }
                    
                    else if (command.equals("-c")) {
                        System.out.println("USAGE: -c number must be called after -f call");
                    }
                
                    else if (command.equals("-f")) {
                        if (i == args.length-1){ System.out.println("USAGE: -f filename");}
                        else {
                            int circleLength = 0;
                            String certName = "null";
                            String fileName = args[++i];
                            
                            int limit = Math.min(args.length,i+5);
                            for(int j = i+1; j < args.length; j++){
                                if( args[j].equals("-c")){
                                    circleLength = Integer.parseInt(args[++j]);
                                    i = i+2;
                                }
                                else if( args[j].equals("-n")){
                                    if (args[++j].endsWith(".crt") || args[j].endsWith(".cer")){
                                        certName = args[j];
                                        i = i+2;
                                    }
                                    else {
                                        System.out.println("USAGE: -n certificateName");
                                        System.exit(-1);
                                    }
                                }
                            }
                            
                            client.fetchFile( fileName, circleLength, certName);
                        }
                    }
                    
                    else if (command.equals("-h")) {
                        if (i == args.length-1){ System.out.println("USAGE: -h hostname:port");}
                        else { client.findIP( args[++i]);}
                    }
                    
                    else if (command.equals("-l")) {
                        client.listFiles();
                    }
                    
                    else if (command.equals("-n")) {
                        System.out.println("USAGE: -n certificateName must be called after -f call");
                    }
                
                    else if (command.equals("-u")) {
                        if (i == args.length-1){
                            System.out.println("USAGE: -u certificate");
                            System.exit(-1);
                        }
                        else if (args[++i].endsWith(".crt") || args[i].endsWith(".cer")){
                            out = new ObjectOutputStream(sock.getOutputStream());
                            out.writeObject(args[i]);
                            out.flush();
                            client.addCert(args[i]);
                            certificate = args[i];
                        }
                        else {
                            System.out.println("Certificate is incorrect format please use .crt or .cer");
                            System.exit(-1);
                        }
                    }
                    
                    else if (command.equals("-v")) {
                        if (i >= args.length-2){
                            System.out.println("USAGE: -v filename certificate");
                            System.exit(-1);
                        }
                        i = i+2;
                        if (args[i].endsWith(".crt") || args[i].endsWith(".cer")){
                            if (!certificate.equals(args[i])){
                                System.out.println("You don't have permission to vouch with this certificate");
                                System.exit(-1);
                            }
                            client.vouchFile(args[i-1],args[i]);
                        }
                        else {
                            System.out.println("Certificate is incorrect format please use .crt or .cer");
                            System.exit(-1);
                        }
                    }
                    
                    else {
                        System.out.println("Invalid argument");
                        System.exit(-1);
                    }
                try {
                    sock.close();
                    sock = (SSLSocket) sslsocketfactory.createSocket(host, port);
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject("none");
                    out.flush();
                }
                catch (IOException e) {
                    System.out.println(e.getMessage());
                    System.exit(-1);
                }
            }
            
            try {
                sock.close();
                sock = (SSLSocket) sslsocketfactory.createSocket(host, port);
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("none");
                out.flush();
            }
            catch (IOException e) {
                System.out.println(e.getMessage());
                System.exit(-1);
            }
            
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject("");
            out.flush();
            
            in = new ObjectInputStream(sock.getInputStream());
            int server_count = (Integer)in.readObject();
            
            //Acknowledgement that correct number of commands were received
            //Was not able to fully implemented so just took out
            
//            if (client_count != server_count) {
//                System.out.println(server_count);
//                System.out.println("Server did not recieve the correct number of commands, trying again");
//                System.out.println(client_count);
//
//                if (timeout <= 1000) {
//                    timeout += 100;
//                    try {
//                        Thread.sleep(timeout);
//                        client.main(args);
//                    } catch(InterruptedException ex){
//                        Thread.currentThread().interrupt();
//                    }
//                }
//                else {
//                    System.out.println("Server timed out, please check connection between Server and Client");
//                    System.exit(-1);
//                }
//            }
            
        } catch(ClassNotFoundException classnot){
            System.err.println("Data received in unknown format");
            
        } finally {
            if (fis != null) fis.close();
            if (bis != null) bis.close();
            if (is != null) is.close();
            if (os != null) os.close();
            if (sock != null) sock.close();
       
         }
    }
}