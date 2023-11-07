package com.mvas.client.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;
import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class ClientController {

    private RSAPublicKey clientPublicKey;
    private RSAPrivateKey clientPrivateKey;
    @GetMapping("/")
    public String toIndex(){
        return "index";
    }

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestBody String message, Model model) {
        try {
            System.out.println(message);
            List<String> encryptedBlocks = encryptWithServerPublicKey(message);
            System.out.println(encryptedBlocks);
            String response = sendEncryptedBlocksToServer(encryptedBlocks);
            model.addAttribute("response", "Сообщение получено: " + response);
            System.out.println(response);
        } catch (Exception e) {
            model.addAttribute("response", "Error: " + e.getMessage());
        }
        return "result";
    }

    private List<String> encryptWithServerPublicKey(String message) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/getServerPublicKey";
        String serverPublicKeyBase64 = restTemplate.postForObject(serverUrl, null, String.class);
        RSAPublicKey serverPublicKey = decodeRSAPublicKey(serverPublicKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        System.out.println(cipher);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
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
