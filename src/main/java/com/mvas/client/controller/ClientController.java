package com.mvas.client.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Controller
public class ClientController {

    private RSAPrivateKey clientPrivateKey;
    public ClientController() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRSAKeyPair();
        clientPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey clientPublicKey = (RSAPublicKey) keyPair.getPublic();

        sendClientPublicKeyToServer(clientPublicKey);
    }
    // Настройка адреса сайта
    @GetMapping("/")
    public String toIndex() {
        return "index";
    }

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestParam String message, Model model) {
        try {
            String encryptedData = encryptWithServerPublicKey(message);
            String response = sendEncryptedDataToServer(encryptedData);
            String decryptedResponse = decryptWithClientPrivateKey(response);
            model.addAttribute("response", decryptedResponse);
        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }
        return "result";
    }
    private void sendClientPublicKeyToServer(RSAPublicKey publicKey) {
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveClientPublicKey";
        restTemplate.postForObject(serverUrl, Base64.getEncoder().encodeToString(publicKey.getEncoded()), String.class);
    }

    private String decryptWithClientPrivateKey(String encryptedData) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String[] parts = encryptedData.split(":");

        Cipher rsaCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] encryptedAesKey = Base64.getDecoder().decode(parts[0]);
        byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

        SecretKeySpec aesKey = new SecretKeySpec(decryptedAesKey, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] encryptedMessage = Base64.getDecoder().decode(parts[1]);
        byte[] decryptedMessage = aesCipher.doFinal(encryptedMessage);

        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    // Шифрование с помощью AES и RSA методов шифрования
    private String encryptWithServerPublicKey(String message) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/getServerPublicKey";
        String serverPublicKeyBase64 = restTemplate.postForObject(serverUrl, null, String.class);
        RSAPublicKey serverPublicKey = decodeRSAPublicKey(serverPublicKeyBase64);
        Cipher rsaCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMessage = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedAesKey) + ":" + Base64.getEncoder().encodeToString(encryptedMessage);
    }

    private RSAPublicKey decodeRSAPublicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private String sendEncryptedDataToServer(String encryptedData) {
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveEncryptedData";
        return restTemplate.postForObject(serverUrl, encryptedData, String.class);
    }
}
