package com.mvas.client.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Controller
public class ClientController {
    private static final Logger logger = LogManager.getLogger(ClientController.class);
    private RSAPublicKey clientPublicKey;
    private RSAPrivateKey clientPrivateKey;

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestBody String message, Model model) {
        try {
            logger.info("/sendMessage");
            String encryptedMessage = encryptWithServerPublicKey(message);
            logger.info("EncryptedMessage: " + encryptedMessage);
            String response = sendEncryptedMessageToServer(encryptedMessage);
            logger.info("Response: " + response);

            model.addAttribute("response", "Сообщение получено: " + response);
            logger.info("Model add Attribute response");

        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }

        return "result";
    }

    private String encryptWithServerPublicKey(String message) throws Exception {
        logger.info("Encrypt With Server Public Key");
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/getServerPublicKey";
        logger.info("POST for object");
        String serverPublicKeyBase64 = restTemplate.postForObject(serverUrl, null, String.class);

        RSAPublicKey serverPublicKey = decodeRSAPublicKey(serverPublicKeyBase64);
        logger.info("Server Public Key: " + serverPublicKey);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8")); // Указываем кодировку
        logger.info("Encrypted Bytes: " + encryptedBytes);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private RSAPublicKey decodeRSAPublicKey(String publicKeyBase64) throws Exception {
        logger.info("Decode RSA Public Key");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        logger.info("Public Key Bytes: " + publicKeyBytes);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        logger.info("X509EncodedKeySpec: " + keySpec);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private String sendEncryptedMessageToServer(String encryptedMessage) {
        logger.info("Send Encrypted Message To Server");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        HttpEntity<String> request = new HttpEntity<>(encryptedMessage, headers);

        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveMessage";
        String response = restTemplate.postForObject(serverUrl, request, String.class);
        logger.info("Response: " + response);
        try {
            response = new String(response.getBytes(StandardCharsets.ISO_8859_1), "UTF-8"); // Декодирование из ISO-8859-1 в UTF-8
            logger.info(("Decrypt response: " + response));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return response;
    }
}
