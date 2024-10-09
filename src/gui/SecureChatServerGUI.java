package gui;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

public class SecureChatServerGUI {
    private static final byte[] STATIC_KEY = "1234567890123456".getBytes();
    private SecretKey secretKey;

    private JFrame frame;
    private JTextArea logArea;

    public SecureChatServerGUI() {
        secretKey = new SecretKeySpec(STATIC_KEY, "AES");
        initialize();
    }

    private void initialize() {
        frame = new JFrame("Secure Chat Server");
        frame.setSize(400, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        frame.getContentPane().add(new JScrollPane(logArea), BorderLayout.CENTER);

        frame.setVisible(true);

        startServer();
    }

    private void startServer() {
        new Thread(() -> {
            try {
                InetAddress localHost = InetAddress.getLocalHost();
                String host = localHost.getHostAddress();
                String encryptedIp = encryptMessage(host);
                logArea.append("Ваш зашифрованный IP-адрес: " + encryptedIp + "\n");

                try (ServerSocket serverSocket = new ServerSocket(12345, 50, InetAddress.getByName(host))) {
                    logArea.append("Сервер запущен и ожидает подключения на " + host + "...\n");

                    while (true) {
                        Socket socket = serverSocket.accept();
                        logArea.append("Клиент подключился!\n");


                        ObjectOutputStream keyOut = new ObjectOutputStream(socket.getOutputStream());
                        keyOut.writeObject(secretKey.getEncoded());

                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                        String encryptedMessage = in.readLine();
                        logArea.append("Получено зашифрованное сообщение: " + encryptedMessage + "\n");

                        String decryptedMessage = decryptMessage(encryptedMessage);
                        logArea.append("Расшифрованное сообщение: " + decryptedMessage + "\n");


                        String response = "Сообщение получено!";
                        String encryptedResponse = encryptMessage(response);
                        out.println(encryptedResponse);
                    }
                }
            } catch (Exception e) {
                logArea.append("Ошибка: " + e.getMessage() + "\n");
                e.printStackTrace();
            }
        }).start();
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
        EventQueue.invokeLater(() -> {
            try {
                new SecureChatServerGUI();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}