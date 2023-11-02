package com.mvas.client.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
public class ClientController {

    @PostMapping("/sendMessage")
    public String sendMessage(@RequestParam("message") String message, Model model) {
        // Создайте HttpHeaders и установите заголовок "Content-Type"
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Создайте HttpEntity с параметром "message"
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("message", message);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        // Отправьте POST-запрос на сервер
        RestTemplate restTemplate = new RestTemplate();
        String serverUrl = "http://localhost:8081/receiveMessage";
        String response = restTemplate.postForObject(serverUrl, request, String.class);

        model.addAttribute("response", "Текст получен " + response);

        return "result";
    }
}
