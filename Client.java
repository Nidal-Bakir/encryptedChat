
package encryptedChat;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 5555);
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            Scanner scanner = new Scanner(System.in);


            System.out.println("from home_work.Server: " + ois.readUTF());

            int algorithmNumber = scanner.nextInt();

            oos.writeInt(algorithmNumber);
            oos.flush();

            Algorithm.startEncryptedChat(algorithmNumber, ois, oos, false);

        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException | NoSuchPaddingException | NoSuchAlgorithmException | ClassNotFoundException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

}
