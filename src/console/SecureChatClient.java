package console;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

public class SecureChatClient {
    private static final byte[] STATIC_KEY = "1234567890123456".getBytes();
    private SecretKey secretKey;

    public SecureChatClient() {
        secretKey = new SecretKeySpec(STATIC_KEY, "AES");
    }

    public String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptMessage(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            SecureChatClient client = new SecureChatClient();
            Scanner scanner = new Scanner(System.in);

            System.out.print("Введите зашифрованный IP-адрес сервера: ");
            String encryptedIp = scanner.nextLine();


            String decryptedIp = client.decryptMessage(encryptedIp);
            System.out.println("Расшифрованный IP-адрес: " + decryptedIp);

            try (Socket socket = new Socket(decryptedIp, 12345)) {
                System.out.println("Подключение к серверу...");


                ObjectInputStream keyIn = new ObjectInputStream(socket.getInputStream());
                byte[] keyBytes = (byte[]) keyIn.readObject();


                SecureChatClient sessionClient = new SecureChatClient();
                sessionClient.secretKey = new SecretKeySpec(keyBytes, "AES");

                BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                System.out.print("Введите сообщение: ");
                String message = consoleInput.readLine();

                String encryptedMessage = sessionClient.encryptMessage(message);
                out.println(encryptedMessage);

                String encryptedResponse = in.readLine();
                String response = sessionClient.decryptMessage(encryptedResponse);
                System.out.println("Ответ от сервера: " + response);

            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}