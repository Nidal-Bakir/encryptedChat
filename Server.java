
package encryptedChat;

import Lab_3_rsa.RSA;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Server {
    ServerSocket sersoc = null;
    Socket socket = null;
    ObjectInputStream ois;
    ObjectOutputStream oos;

    public Server() {
        try {
            sersoc = new ServerSocket(5555);
            System.out.println("home_work.Server started");
            socket = sersoc.accept();
            System.out.println("home_work.Client Connected");
            ois = new ObjectInputStream(socket.getInputStream());
            oos = new ObjectOutputStream(socket.getOutputStream());

            String stringBuffer = "choose the encryption algorithm: (Send the number of the required algorithm)\n" +
                    "1) Caesar\n" +
                    "2) DES/CBC/PkCS5Padding\n" +
                    "3) AES/CBC/PkCS5Padding\n" +
                    "4) RSA\n";
            oos.writeUTF(stringBuffer);
            oos.flush();

            int algorithmNumber = ois.readInt();

            Algorithm.startEncryptedChat(algorithmNumber, ois, oos, true);


        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        new Server();
    }

}
