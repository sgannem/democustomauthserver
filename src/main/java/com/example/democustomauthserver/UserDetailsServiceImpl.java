package com.example.democustomauthserver;

import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
public class UserDetailsServiceImpl implements UserDetailsService {

  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
//    User domainUser = userService.findByLogin(username);
//    if (domainUser == null) {
//      throw new UsernameNotFoundException("Could not find user with name '" + username + "'");
//    }
//    List<GrantedAuthority> roles = SecurityUtil.getRoles(domainUser);
//    return new UserDetailsImpl(domainUser, roles);
//  }
    User user = new User(userName, "1234");
    List<GrantedAuthority> roles = new ArrayList<>();
    return new UserDetailsImpl(user, roles);
  }
}
