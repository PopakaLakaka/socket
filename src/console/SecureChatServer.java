package console;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

public class SecureChatServer {
    private static final byte[] STATIC_KEY = "1234567890123456".getBytes();
    private SecretKey secretKey;

    public SecureChatServer() {
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
            SecureChatServer server = new SecureChatServer();
            Scanner scanner = new Scanner(System.in);

            System.out.println("Выберите способ запуска сервера:");
            System.out.println("1. localhost");
            System.out.println("2. IP-адрес машины");
            int choice = scanner.nextInt();
            scanner.nextLine();

            String host = "localhost";
            if (choice == 2) {
                InetAddress localHost = InetAddress.getLocalHost();
                host = localHost.getHostAddress();
                String encryptedIp = server.encryptMessage(host);
                System.out.println("Ваш зашифрованный IP-адрес: " + encryptedIp);
            }

            try (ServerSocket serverSocket = new ServerSocket(12345, 50, InetAddress.getByName(host))) {
                System.out.println("Сервер запущен и ожидает подключения на " + host + "...");
                Socket socket = serverSocket.accept();
                System.out.println("Клиент подключился!");


                ObjectOutputStream keyOut = new ObjectOutputStream(socket.getOutputStream());
                keyOut.writeObject(server.secretKey.getEncoded());

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                String encryptedMessage = in.readLine();
                System.out.println("Получено зашифрованное сообщение: " + encryptedMessage);

                String decryptedMessage = server.decryptMessage(encryptedMessage);
                System.out.println("Расшифрованное сообщение: " + decryptedMessage);


                String response = "Сообщение получено!";
                String encryptedResponse = server.encryptMessage(response);
                out.println(encryptedResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}