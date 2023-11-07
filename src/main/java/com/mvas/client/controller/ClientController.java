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
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Controller
public class ClientController {

    @GetMapping("/")
    public String toIndex() {
        return "index";
    }

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestParam String message, Model model) {
        try {
            System.out.println(message);
            String encryptedData = encryptWithServerPublicKey(message);
            System.out.println(encryptedData);
            String response = sendEncryptedDataToServer(encryptedData);
            System.out.println(response);
            model.addAttribute("response", response);
        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }
        return "result";
    }

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
        byte[] encryptedMessage = aesCipher.doFinal(message.getBytes("UTF-8"));

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
