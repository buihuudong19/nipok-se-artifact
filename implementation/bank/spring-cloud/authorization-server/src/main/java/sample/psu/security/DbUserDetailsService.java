//CHECKSTYLE:OFF
package sample.psu.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import sample.psu.store.CustomerCredentialRepository;

/**
 * UserDetailsService nạp credential PASSWORD (PHC) từ PostgreSQL. DaoAuthenticationProvider so khớp
 * raw-password với PHC qua {@link Argon2idPasswordEncoder}.
 *
 * <p>STRIDE-I (chống user-enumeration): user lạ ⇒ UsernameNotFoundException; DaoAuthenticationProvider
 * (hideUserNotFoundExceptions=true mặc định) trả BadCredentials + chạy 1 encode giả để đều timing.
 */
public final class DbUserDetailsService implements UserDetailsService {

  private final CustomerCredentialRepository credentials;

  public DbUserDetailsService(CustomerCredentialRepository credentials) {
    this.credentials = credentials;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return credentials.findByCustomer_UsernameAndMethodAndEnabledTrue(username, "PASSWORD")
        .map(c -> User.withUsername(username)
            .password(c.getCredential())   // PHC — KHÔNG re-encode (không dùng withDefaultPasswordEncoder)
            .roles("USER")
            .build())
        .orElseThrow(() -> new UsernameNotFoundException("no PASSWORD credential for " + username));
  }
}
//CHECKSTYLE:ON
