package com.mvas.client.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class ClientController {
    @GetMapping("/")
    public String toIndex(){
        return "index";
    }
    private RSAPublicKey clientPublicKey;
    private RSAPrivateKey clientPrivateKey;

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestParam String message, Model model) {
        try {
            List<String> encryptedBlocks = encryptWithServerPublicKey(message);
            String response = sendEncryptedBlocksToServer(encryptedBlocks);
            model.addAttribute("response", response);
        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }
        return "result";
    }

    private List<String> encryptWithServerPublicKey(String message) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/getServerPublicKey";
        String serverPublicKeyBase64 = restTemplate.postForObject(serverUrl, null, String.class);
        RSAPublicKey serverPublicKey = decodeRSAPublicKey(serverPublicKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        byte[] messageBytes = message.getBytes("UTF-8");
        int inputLen = messageBytes.length;
        int blockSize = 245;
        List<String> encryptedBlocks = new ArrayList<>();

        for (int i = 0; i < inputLen; i += blockSize) {
            int currentBlockSize = Math.min(blockSize, inputLen - i);
            byte[] block = cipher.doFinal(messageBytes, i, currentBlockSize);
            encryptedBlocks.add(Base64.getEncoder().encodeToString(block));
        }

        return encryptedBlocks;
    }

    private RSAPublicKey decodeRSAPublicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private String sendEncryptedBlocksToServer(List<String> encryptedBlocks) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<List<String>> request = new HttpEntity<>(encryptedBlocks, headers);
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveFile";
        return restTemplate.postForObject(serverUrl, request, String.class);
    }
}
