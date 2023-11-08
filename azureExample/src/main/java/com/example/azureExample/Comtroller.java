package com.example.azureExample;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class Comtroller {

        @GetMapping("/")
        @PreAuthorize("hasAuthority('APPROLE_AdminRole')")
        public String Admin() {
            // return new Message("Admin message");
            return "sssssssshjyjrndryj";
        }

        @GetMapping("/api")
        public String send(Authentication authentication ){
            return "Id token /n "+ authentication;
        }

}

