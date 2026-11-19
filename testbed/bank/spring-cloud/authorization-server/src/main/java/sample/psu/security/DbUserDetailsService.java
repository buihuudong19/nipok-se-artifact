//CHECKSTYLE:OFF
package sample.psu.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import sample.psu.store.CustomerCredentialRepository;

/**
 * UserDetailsService loading PASSWORD credentials (PHC) from PostgreSQL. DaoAuthenticationProvider matches
 * the raw password against the PHC through {@link Argon2idPasswordEncoder}.
 *
 * <p>STRIDE information disclosure (against user enumeration): unknown user => UsernameNotFoundException; DaoAuthenticationProvider
 * (hideUserNotFoundExceptions=true by default) returns BadCredentials and runs one dummy encode to equalise the timing.
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
            .password(c.getCredential())   // PHC - NOT re-encoded (withDefaultPasswordEncoder not used)
            .roles("USER")
            .build())
        .orElseThrow(() -> new UsernameNotFoundException("no PASSWORD credential for " + username));
  }
}
//CHECKSTYLE:ON
