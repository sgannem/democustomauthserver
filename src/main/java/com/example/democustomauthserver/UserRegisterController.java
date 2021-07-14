package com.example.democustomauthserver;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRegisterController {
  @PostMapping(value = "/signup", produces = "application/json", consumes = "application/json" )
  public String register(@RequestBody User user) {
    System.out.println(user);
    return "success";
  }
}
