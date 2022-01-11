//CITS 3002 Project by:
//Robert Pennefather - 21511164
//Lukas Pfeifle - 21493735

import java.io.*;
import java.nio.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

public class Server {
    
    static SSLServerSocket servsock = null;
    static SSLSocket sock = null;
    
    static FileInputStream fis = null;
    static BufferedInputStream bis = null;
    static InputStream is = null;
    static ObjectInputStream in = null;
    
    static FileOutputStream fos = null;
    static BufferedOutputStream bos = null;
    static OutputStream os = null;
    static ObjectOutputStream out = null;
    
    static String oldtrustyPath =  System.getProperty("user.dir") + File.separator + "oldtrusty";
    static String[] currentPath = new String[10000];
    static int directoryCount = 0;
    
    Server(){}
    
    public final static int FILE_SIZE = 3145729; //3MB
    
    void addFile(int clientNum) {
        
        try {
            
            int bytesRead;
            int current = 0;
            
            //read file name
            in = new ObjectInputStream(sock.getInputStream());
            String fileName = (String)in.readObject();
            
            if( fileName.equals("ERROR")){ return;}
            
            //determine if file can be added
            String exist = findExist(clientNum, fileName, oldtrustyPath);
            if (!exist.equals("null")){
                exist = findExist(clientNum, fileName, currentPath[clientNum]);
                if (exist.equals("null")){
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject("no");
                    out.flush();
                    return;
                }
            }
            
            out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject("yes");
            out.flush();
            
            // receive file
            byte [] mybytearray  = new byte [FILE_SIZE];
            is = sock.getInputStream();
            File newFile = new File (currentPath[clientNum], fileName);
            fos = new FileOutputStream(newFile);
            bos = new BufferedOutputStream(fos);
            bytesRead = is.read(mybytearray,0,mybytearray.length);
            current = bytesRead;
            
            do {
                bytesRead =
                is.read(mybytearray, current, (mybytearray.length-current));
                if(bytesRead >= 0) current += bytesRead;
            } while(bytesRead > -1);
            
            bos.write(mybytearray, 0 , current);
            bos.flush();
            System.out.println("File " + fileName + " downloaded (" + current + " bytes read)");
            
            if (!(fileName.endsWith(".crt") || fileName.endsWith(".cer"))){
                File trustFile = null;
                
                File file = new File( currentPath[clientNum] );
                File[] list = file.listFiles();
                if (list != null) {
                    for (File fil : list) {
                        if (fil.getName().contains("trust")) {
                            trustFile = fil.getAbsoluteFile();
                        }
                    }
                }
                
                //Read from file
                FileReader trustFileRead =  new FileReader(trustFile);
                
                String data = "";
                String sCurrentLine;
                BufferedReader br = new BufferedReader(trustFileRead);
                while ((sCurrentLine = br.readLine()) != null) {
                    data = data + sCurrentLine + "\n";
                }
            
                //Check not already trusted
                if(!data.contains(fileName)){
                    
                    //Write to file
                    FileWriter trustFileWrite =  new FileWriter(trustFile);
                    
                    BufferedWriter bw = new BufferedWriter(trustFileWrite);
                    bw.write(data + "\n" + fileName);
                    bw.close();
                    
                }
            }
        }
        catch(ClassNotFoundException classnot){
            System.err.println("Data received in unknown format");
        }
        catch(IOException e){
            System.out.println(e.getMessage());
        } finally {
            if (fos != null){ fos = null;}
            if (bos != null){ bos = null;}
        }
    }
    
    int certNum( String path){
        int count = 0;
        File root = new File( path );
        File[] list = root.listFiles();
        
        if (list == null) return 0;
        for ( File f : list ) {
            if ( f.isDirectory() ) {
                count += certNum( f.getAbsolutePath() );
            }
            //only count certificates
            else if ( f.getName().endsWith(".crt") || f.getName().endsWith(".cer")) {
                count++;
            }
        }
        return count;
    }
    
    boolean trustFile(String fileName, String path){
        File root = new File( path );
        File[] list = root.listFiles();
        
        if (list == null) return false;
        for ( File f : list ) {
            if ( f.isDirectory() ) {
                return trustFile( fileName, f.getAbsolutePath() );
            }
            else if ( f.getName().contains("trust")) {
                
                try {
                    //Read from file
                    FileReader trustFileRead =  new FileReader(f.getAbsoluteFile());
                    
                    String data = "";
                    String sCurrentLine;
                    BufferedReader br = new BufferedReader(trustFileRead);
                    while ((sCurrentLine = br.readLine()) != null) {
                        data = data + sCurrentLine + "\n";
                    }
                    if(data.contains(fileName)){
                        return true;
                    }
                } catch(IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return false;
    }
    
    void fetchFile( int clientNum) {
        
        try {
            
            //read parameters
            ObjectInputStream in = new ObjectInputStream(sock.getInputStream());
            String fileName = (String)in.readObject();
            int circleLength = (Integer)in.readObject();
            String certName = (String)in.readObject();
            
            String filePath = findExist(clientNum, fileName, oldtrustyPath);
            if(!(filePath.equals("null") || fileName.contains("trust"))) {
                
                //Change current path
                currentPath[clientNum] = filePath;
                currentPath[clientNum] = currentPath[clientNum].substring(0, currentPath[clientNum].length() - fileName.length() - 1);
                
                //Check parameters
                if (circleLength > 0){
                    boolean fail = true;
                    for(int i=1; i < directoryCount; i++){
                        String newPath = oldtrustyPath + File.separator + ("circle" + i);
                        if (trustFile( fileName, newPath)){
                            if (circleLength <= certNum( newPath )){
                                fail = false;
                                break;
                            }
                        }
                    } if (fail == true){
                        out = new ObjectOutputStream(sock.getOutputStream());
                        out.writeObject("c");
                        out.flush();
                        return;
                    }
                }
                if (!certName.equals("null")){
                    boolean fail = true;
                    for(int i=1; i < directoryCount; i++){
                        String newPath = oldtrustyPath + File.separator + ("circle" + i);
                        if (trustFile( fileName, newPath)){
                            if (!findExist(clientNum, certName, newPath).equals("null")){
                                fail = false;
                                break;
                            }
                        }
                    } if (fail == true){
                        out = new ObjectOutputStream(sock.getOutputStream());
                        out.writeObject("n");
                        out.flush();
                        return;
                    }
                }
                
                // confirm file exists
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("ready");
                out.flush();
                
                //send file
                File myFile = new File (currentPath[clientNum], fileName);
                byte [] mybytearray  = new byte [(int)myFile.length()];
                fis = new FileInputStream(myFile);
                bis = new BufferedInputStream(fis);
                bis.read(mybytearray,0,mybytearray.length);
                os = sock.getOutputStream();
                System.out.println("Sending " + fileName + "(" + mybytearray.length + " bytes)");
                os.write(mybytearray,0,mybytearray.length);
                os.flush();
                System.out.println("Done.");
            
            } else {
                
                // send error message
                out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("ERROR");
                out.flush();
            }
        }
        catch(ClassNotFoundException classnot){
            System.err.println("Data received in unknown format");
        }
        catch(IOException ioException){
            ioException.printStackTrace();
        } finally {
            try {
                if (bis != null) bis.close();
                if (os != null) os.close();
            } catch (IOException e){
                System.out.println(e.getMessage());
            }
        }
    }
    
    String listCerts (String path ) {
        
        String certList = "";
        // list files
        File root = new File( path );
        File[] list = root.listFiles();
        
        if (list == null) return "";
        
        for ( File f : list ) {
            if ( f.isDirectory() ) {
                certList = certList + listCerts( f.getAbsolutePath() );
            }
            //Print only certificates
            else if (f.getName().endsWith(".crt") || f.getName().endsWith(".cer")) {
                certList = certList + f.getName() + ", ";
            }
        }
        certList = certList.substring(0, certList.length() - 2);
        return certList;
    }
        
    String findFiles (int clientNum, String path ) {
    
        String fileList = "";
        // list files
        File root = new File( path );
        File[] list = root.listFiles();
        
        if (list == null) return "";
        
        for ( File f : list ) {
            if ( f.isDirectory() ) {
                fileList = fileList + findFiles(clientNum, f.getAbsolutePath() );
            }
            //Do not print the formatting file
            else if (!(f.getName().equals(".DS_Store") || f.getName().endsWith(".crt")
                       || f.getName().endsWith(".cer") || f.getName().contains("trust"))) {
                
                fileList = fileList + "'" + f.getName() + "':\n";
                
                for(int i=1; i < directoryCount; i++){
                    String newPath = oldtrustyPath + File.separator + ("circle" + i);
                    if (trustFile( f.getName(), newPath)){
                        int circleLength = certNum(newPath);
                        String certList = listCerts (newPath);
                        fileList = fileList + "\t" + circleLength + ": " + certList + "\n";
                    }
                }
                fileList = fileList + "\n";
            }
        }        
        return fileList;
    }
    
    void listFiles(int clientNum) {
        
        String fileList = "------------------------"
                        + "\n\nServer file list:\n"
                        + "\tCircle of trust length: Trusting certificates\n\n"
                        + findFiles(clientNum, oldtrustyPath)
                        + "------------------------";
                        
        try {
            // send total list to client
            ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
            out.writeObject(fileList);
            out.flush();
        }
        catch(IOException e){
            System.out.println(e.getMessage());
        }
    }
    
    String findExist(int clientNum, String name, String dir) {
        File file = new File( dir );
        File[] list = file.listFiles();
        if (list != null) {
            for (File fil : list) {
                String path = "null";
                if (fil.isDirectory()) {
                    path = findExist(clientNum, name, fil.getAbsolutePath());
                    if (path != "null") {
                        return path;
                    }
                } else if (fil.getName().equals(name) && !fil.getName().equals(".DS_Store")) {
                    path = fil.getAbsolutePath();
                    if (path != "null") {
                        return path;
                    }
                }
            }
        }
        return "null"; // nothing found
    }
    
    void addCertificate(int clientNum, String certificateName) {
        
        try {
        
            String certificatePath = findExist(clientNum, certificateName, oldtrustyPath);
            
            //See if certificate is already in server
            if(certificatePath.equals("null")) {

                ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("notExist");
                out.flush();
                
                in = new ObjectInputStream(sock.getInputStream());
                String warning = (String)in.readObject();
                if (!warning.equals("ERROR")){
                
                    //create new directory
                    String dir = oldtrustyPath + File.separator + ("circle" + directoryCount);
                    boolean successful = new File(dir).mkdir();
                    
                    //change the path to this directory
                    if(successful) {
                        //add trust file
                        File trustfile = new File(dir + File.separator + "trust" + directoryCount + ".txt");
                        if (!trustfile.createNewFile()){
                            System.out.println("ERROR: File couldn't be created");
                            System.exit(-1);
                        }
                        
                        currentPath[clientNum] = oldtrustyPath + File.separator + ("circle" + directoryCount);
                        directoryCount++;
                        
                        addFile(clientNum);
                    }
                    else {
                        //ERROR
                    }
                }
            }
            else {
                ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("exist");
                out.flush();
                
                currentPath[clientNum] = certificatePath;
                currentPath[clientNum] = currentPath[clientNum].substring(0, currentPath[clientNum].length() - certificateName.length() - 1);
            }
        } catch(ClassNotFoundException classnot){
            System.err.println("Arguments are unknown format");
        } catch(IOException e){
            System.out.println(e.getMessage());
        }
    }
    
    void vouchFile(int clientNum, String fileName, String certificateName) {
        
        try {
            
            String filePath = findExist(clientNum, fileName, oldtrustyPath);
            String certificatePath = findExist(clientNum, certificateName, oldtrustyPath);
            
            //See if file and certificate is already in server
            if(filePath.equals("null") || certificatePath.equals("null")) {
                
                ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("notExist");
                out.flush();
                
            } else {
                ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
                out.writeObject("exist");
                out.flush();
                
                currentPath[clientNum] = certificatePath;
                currentPath[clientNum] = currentPath[clientNum].substring(0, currentPath[clientNum].length() - certificateName.length() - 1);
                
                File trustFile = null;
                
                File file = new File( currentPath[clientNum] );
                File[] list = file.listFiles();
                if (list != null) {
                    for (File fil : list) {
                        if (fil.getName().contains("trust")) {
                            trustFile = fil.getAbsoluteFile();
                        }
                    }
                }
                
                //Read from file
                FileReader trustFileRead =  new FileReader(trustFile);
                
                String data = "";
                String sCurrentLine;
                BufferedReader br = new BufferedReader(trustFileRead);
                while ((sCurrentLine = br.readLine()) != null) {
                    data = data + sCurrentLine + "\n";
                }
                
                //Check not already trusted
                if(!data.contains(fileName)){
                    
                    //Write to file
                    FileWriter trustFileWrite =  new FileWriter(trustFile);
                    
                    BufferedWriter bw = new BufferedWriter(trustFileWrite);
                    bw.write(data + "\n" + fileName);
                    bw.close();
                    
                }
            }
        } catch(IOException e){
            System.out.println(e.getMessage());
        }
    }

    
    public static void main (String [] args ) throws IOException {
        
        Server server = new Server();
        
        int port = -1;
        
        if (args.length < 1) {
            System.out.println("USAGE: java Server port");
            System.exit(-1);
        }

        try {
            port = Integer.parseInt(args[0]);
        } catch (IllegalArgumentException e) {
            System.out.println("USAGE: java Server " +
                               "port");
            System.exit(-1);
        }
       
        int server_count = 0;
        int server_count_reset = 0;
        
        try {
            SSLServerSocketFactory sslserversocketfactory =
            (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            servsock =
            (SSLServerSocket) sslserversocketfactory.createServerSocket(port);
            
            while (true) {
                System.out.println("Waiting...");
                try {
                    
                    sock = (SSLSocket) servsock.accept();
                    System.out.println("Accepted connection : " + sock);
                    directoryCount = new File(oldtrustyPath).listFiles().length;
                    
                    int clientNum = 0; //Intialise
                    
                    //read certificate name
                    in = new ObjectInputStream(sock.getInputStream());
                    String certificateName = (String)in.readObject();
                    if (!certificateName.equals("none")){
                        in = new ObjectInputStream(sock.getInputStream());
                        clientNum = (Integer)in.readObject();
                        currentPath[clientNum] = oldtrustyPath;
                        server.addCertificate(clientNum, certificateName);
                    }
                    
                    //read command
                    in = new ObjectInputStream(sock.getInputStream());
                    String command = (String)in.readObject();
                    System.out.println(command);
                    if (command.length() >=2) {
                        clientNum = Integer.valueOf(command.substring(0, command.length()-2));
                        command = command.substring(command.length()-2, command.length());
                    }
                    System.out.println(command);
                    
                    while (!command.equals(null)){
                        
                        server_count++;
                        server_count_reset = server_count;
                        
                        //using this over switch statement as old java is on lab computers
                        if (command.equals("-a" )) {
                            server.addFile( clientNum);
                        }
                        else if (command.equals("-c" )) {}
                        else if (command.equals("-f" )) {
                            server.fetchFile( clientNum);
                        }
                        else if (command.equals("-h" )) {
                        }
                        else if (command.equals("-l" )) {
                            server.listFiles( clientNum);
                        }
                        else if (command.equals("-n" )) {
                        }
                        else if (command.equals("-u" )) {
                            in = new ObjectInputStream(sock.getInputStream());
                            certificateName = (String)in.readObject();
                            server.addCertificate(clientNum, certificateName);
                        }
                        else if (command.equals("-v" )) {
                            in = new ObjectInputStream(sock.getInputStream());
                            String fileName = (String)in.readObject();
                            in = new ObjectInputStream(sock.getInputStream());
                            certificateName = (String)in.readObject();
                            server.vouchFile(clientNum, fileName, certificateName);
                        }
                        else if (command.equals("")) {
                            server_count--;
                            break;
                        }
                        else {
                            System.out.println("Invalid argument");
                        }
                    
                        
                        in = new ObjectInputStream(sock.getInputStream());
                        command = (String)in.readObject();
                        System.out.println(command);
                        
                    }
                    out = new ObjectOutputStream(sock.getOutputStream());
                    out.writeObject(server_count);
                    out.flush();
                    
                } catch(IOException e){}
                
                finally {
                    if (fis != null) fis.close();
                    if (bis != null) bis.close();
                    if (is != null) is.close();
                    if (fos != null) fos.close();
                    if (bos != null) bos.close();
                    if (os != null) os.close();
                    if (sock != null) sock.close();
                    
                    server_count -= server_count_reset;
                    server_count_reset = 0;
                    if (server_count > 10) { server_count = 0;}
                }
            }
        }
        catch(ClassNotFoundException classnot){
            System.err.println("Arguments are unknown format");
        }
        finally {
            if (servsock != null) servsock.close();
        }
    }
}
