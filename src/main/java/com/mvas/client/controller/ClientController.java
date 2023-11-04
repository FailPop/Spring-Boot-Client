package com.mvas.client.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Controller
public class ClientController {

    private RSAPublicKey clientPublicKey;
    private RSAPrivateKey clientPrivateKey;

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestBody String message, Model model) {
        try {
            String encryptedMessage = encryptWithServerPublicKey(message);

            String response = sendEncryptedMessageToServer(encryptedMessage);

            model.addAttribute("response", "Сообщение получено: " + response);

        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }

        return "result";
    }

    private String encryptWithServerPublicKey(String message) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/getServerPublicKey";
        String serverPublicKeyBase64 = restTemplate.postForObject(serverUrl, null, String.class);

        RSAPublicKey serverPublicKey = decodeRSAPublicKey(serverPublicKeyBase64);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8")); // Указываем кодировку UTF-8
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private RSAPublicKey decodeRSAPublicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private String sendEncryptedMessageToServer(String encryptedMessage) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        HttpEntity<String> request = new HttpEntity<>(encryptedMessage, headers);

        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveMessage";
        String response = restTemplate.postForObject(serverUrl, request, String.class);

        try {
            response = new String(response.getBytes("ISO-8859-1"), "UTF-8"); // Декодирование из ISO-8859-1 в UTF-8
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return response;
    }
}
