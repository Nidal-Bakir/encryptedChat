package encryptedChat;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

abstract class Algorithm {
    boolean isServer;

    static void startEncryptedChat(int algorithmNumber, ObjectInputStream ois, ObjectOutputStream oos, boolean isServer) throws IOException, InterruptedException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
        if (algorithmNumber == 1) {
            new Caesar(ois, oos, isServer);
        } else if (algorithmNumber == 2) {
            new DES(ois, oos, isServer);
        } else if (algorithmNumber == 3) {
            new RSA(ois, oos, isServer);
        }

    }

    ObjectInputStream ois;
    ObjectOutputStream oos;

    public Algorithm(ObjectInputStream ois, ObjectOutputStream oos, boolean isServer) throws InterruptedException, IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, NoSuchPaddingException {
        this.ois = ois;
        this.oos = oos;
        this.isServer = isServer;

        init();
        start();

    }

    void start() throws InterruptedException {


        Thread oosThread = new Thread(() -> {
            Scanner scanner = new Scanner(System.in);
            while (true) {

                try {
                    System.out.print("Send someThings: ");
                    String msg = scanner.nextLine();

                    Object encryptMsg = encrypt(msg);

                    oos.writeObject(encryptMsg);
                    oos.flush();

                } catch (IOException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                         InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }


            }
        });
        oosThread.start();

        Thread oisThread = new Thread(() -> {
            if (isServer) {
                System.out.println("awaiting for the client to sent somethings...\n ");
            } else {
                System.out.println("awaiting for the Server to sent somethings...\n ");
            }

            while (true) {

                try {
                    Object msg = ois.readObject();

                    String encryptMsg = decrypt(msg);

                    if (isServer) {
                        System.out.println("client: " + encryptMsg);
                    } else {
                        System.out.println("Server: " + encryptMsg);
                    }


                } catch (IOException ex) {
                    Logger.getLogger(Algorithm.class.getName()).log(Level.SEVERE, null, ex);
                    throw new RuntimeException(ex);
                } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                         InvalidAlgorithmParameterException | ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }


            }
        });
        oisThread.start();

        // Wait for the child threads to finish
        oisThread.join();
        oosThread.join();


    }

    abstract void init() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, NoSuchPaddingException;

    abstract Object encrypt(String msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException;


    abstract String decrypt(Object msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException;

}

class Caesar extends Algorithm {
    int shiftKey = 0;

    public Caesar(ObjectInputStream ois, ObjectOutputStream oos, boolean isServer) throws InterruptedException, IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, NoSuchPaddingException {
        super(ois, oos, isServer);
    }

    @Override
    void init() throws IOException {
        if (isServer) {
            oos.writeUTF("enter the shift key: ");
            oos.flush();

            shiftKey = ois.readInt();

            oos.writeUTF("The shift key is " + shiftKey);
            oos.flush();
        } else {
            System.out.println(ois.readUTF());

            Scanner scanner = new Scanner(System.in);
            shiftKey = scanner.nextInt();
            oos.writeInt(shiftKey);
            oos.flush();

            System.out.println(ois.readUTF());
        }
    }

    @Override
    String encrypt(String msg) {

        StringBuilder encryptedMsg = new StringBuilder();

        for (int i = 0; i < msg.length(); i++) {
            char c = msg.charAt(i);

            if (Character.isAlphabetic(c)) {
                encryptedMsg.append(encryptChar(c, shiftKey));
            } else {
                encryptedMsg.append(c);
            }
        }

        return encryptedMsg.toString();
    }

    private char encryptChar(char c, int key) {
        char compl = 'A';

        if (Character.isLowerCase(c)) {
            compl = 'a';
        }

        return (char) ((c - compl + key) % 26 + compl);
    }

    private char decryptChar(char c, int key) {
        char compl = 'A';

        if (Character.isLowerCase(c)) {
            compl = 'a';
        }

        if (c - compl >= key) {
            return (char) ((c - key));
        } else {
            return (char) ((c - key + 26));
        }
    }

    @Override
    String decrypt(Object msg) {
        String _msg = (String) msg;

        StringBuilder decryptedMsg = new StringBuilder();

        for (int i = 0; i < _msg.length(); i++) {
            char c = _msg.charAt(i);

            if (Character.isAlphabetic(c)) {
                decryptedMsg.append(decryptChar(c, shiftKey));
            } else {
                decryptedMsg.append(c);
            }
        }

        return decryptedMsg.toString();
    }
}


class DES extends Algorithm {
    Cipher cipher;
    IvParameterSpec iv;

    SecretKey key;

    public DES(ObjectInputStream ois, ObjectOutputStream oos, boolean isServer) throws InterruptedException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
        super(ois, oos, isServer);
    }

    @Override
    void init() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException {

        cipher = Cipher.getInstance("DES/CBC/PkCS5Padding"); // 64 bit block this for DES

        if (isServer) {
            oos.writeUTF("The server will generate the DES secret key....");
            oos.flush();

            key = KeyGenerator.getInstance("DES").generateKey(); // 56 bit key

            oos.writeObject(key);
            oos.flush();


            oos.writeUTF("The server will generate the IV Bytes...");
            oos.flush();

            byte[] ivarr = new byte[8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(ivarr);

            iv = new IvParameterSpec(ivarr);

            oos.writeObject(ivarr);
            oos.flush();

        } else {
            System.out.println(ois.readUTF());

            key = (SecretKey) ois.readObject();

            System.out.println(ois.readUTF());

            byte[] ivarr = (byte[]) ois.readObject();

            iv = new IvParameterSpec(ivarr);

        }


    }


    @Override
    byte[] encrypt(String msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(msg.getBytes());
    }


    @Override
    String decrypt(Object msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] encryptedMessage = (byte[]) msg;
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] encryptedMsg = cipher.doFinal(encryptedMessage);

        return new String(encryptedMsg);
    }
}


class RSA extends Algorithm {
    Cipher cipher;


    PrivateKey privateKey;
    PublicKey publicKey;

    PublicKey otherSidePublicKey;


    public RSA(ObjectInputStream ois, ObjectOutputStream oos, boolean isServer) throws InterruptedException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
        super(ois, oos, isServer);
    }

    @Override
    void init() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, NoSuchPaddingException {

        cipher = Cipher.getInstance("RSA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        if (isServer) {
            oos.writeUTF("The server will generate the RSA public key....");
            oos.flush();

            oos.writeObject(publicKey);
            oos.flush();

            otherSidePublicKey = (PublicKey) ois.readObject();
        } else {
            System.out.println(ois.readUTF());

            otherSidePublicKey = (PublicKey) ois.readObject();

            oos.writeObject(publicKey);
            oos.flush();
        }

    }


    @Override
    byte[] encrypt(String msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, otherSidePublicKey);

        return cipher.doFinal(msg.getBytes());
    }


    @Override
    String decrypt(Object msg) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] encryptedMessage = (byte[]) msg;
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedMsg = cipher.doFinal(encryptedMessage);

        return new String(encryptedMsg);
    }
}

