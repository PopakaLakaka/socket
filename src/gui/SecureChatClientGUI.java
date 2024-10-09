package gui;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class SecureChatClientGUI {
    private static final byte[] STATIC_KEY = "1234567890123456".getBytes();
    private SecretKey secretKey;

    private JFrame frame;
    private JTextField encryptedIpField;
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;

    public SecureChatClientGUI() {
        secretKey = new SecretKeySpec(STATIC_KEY, "AES");
        initialize();
    }

    private void initialize() {
        frame = new JFrame("Secure Chat Client");
        frame.setSize(400, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(new BorderLayout());

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BorderLayout());

        encryptedIpField = new JTextField();
        topPanel.add(new JLabel("Encrypted IP:"), BorderLayout.WEST);
        topPanel.add(encryptedIpField, BorderLayout.CENTER);

        frame.getContentPane().add(topPanel, BorderLayout.NORTH);

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        frame.getContentPane().add(new JScrollPane(chatArea), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BorderLayout());

        messageField = new JTextField();
        bottomPanel.add(messageField, BorderLayout.CENTER);

        sendButton = new JButton("Send");
        bottomPanel.add(sendButton, BorderLayout.EAST);

        frame.getContentPane().add(bottomPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        frame.setVisible(true);
    }

    private void sendMessage() {
        try {
            String encryptedIp = encryptedIpField.getText();
            String decryptedIp = decryptMessage(encryptedIp);

            try (Socket socket = new Socket(decryptedIp, 12345)) {
                chatArea.append("Connected to server...\n");

                ObjectInputStream keyIn = new ObjectInputStream(socket.getInputStream());
                byte[] keyBytes = (byte[]) keyIn.readObject();

                this.secretKey = new SecretKeySpec(keyBytes, "AES");

                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                String message = messageField.getText();
                String encryptedMessage = encryptMessage(message);
                out.println(encryptedMessage);

                String encryptedResponse = in.readLine();
                String response = decryptMessage(encryptedResponse);
                chatArea.append("Server: " + response + "\n");

            } catch (Exception ex) {
                chatArea.append("Error: " + ex.getMessage() + "\n");
                ex.printStackTrace();
            }
        } catch (Exception ex) {
            chatArea.append("Error: " + ex.getMessage() + "\n");
            ex.printStackTrace();
        }
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
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    new SecureChatClientGUI();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}