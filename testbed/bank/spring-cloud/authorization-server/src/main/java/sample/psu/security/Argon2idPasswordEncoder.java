//CHECKSTYLE:OFF
package sample.psu.security;

import java.util.Arrays;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.openbanking.psu.auth.spi.crypto.Argon2idVerifier;
import com.openbanking.psu.auth.spi.model.PasswordHash;
import com.openbanking.psu.auth.spi.model.PasswordInput;

/**
 * Spring {@link PasswordEncoder} adapter -> {@link Argon2idVerifier} (pure SPI).
 * DaoAuthenticationProvider (login) calls {@link #matches}; registration calls {@link #encode}.
 * The cryptography is in the psu-auth-spi module (benchmarked there with JMH); this class only adapts types.
 */
public final class Argon2idPasswordEncoder implements PasswordEncoder {

  private final Argon2idVerifier verifier;

  public Argon2idPasswordEncoder(Argon2idVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  public String encode(CharSequence rawPassword) {
    char[] c = toChars(rawPassword);
    try {
      return verifier.hash(c);
    } finally {
      Arrays.fill(c, '\0');
    }
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    char[] c = toChars(rawPassword);
    try {
      return verifier.verify(new PasswordHash(encodedPassword), new PasswordInput(c), null).ok();
    } finally {
      Arrays.fill(c, '\0');
    }
  }

  private static char[] toChars(CharSequence cs) {
    char[] c = new char[cs.length()];
    for (int i = 0; i < cs.length(); i++) {
      c[i] = cs.charAt(i);
    }
    return c;
  }
}
//CHECKSTYLE:ON
