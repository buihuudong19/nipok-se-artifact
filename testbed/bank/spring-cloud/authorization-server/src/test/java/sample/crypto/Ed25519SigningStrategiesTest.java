package sample.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Behaviour of the registry / factory entry point. */
class Ed25519SigningStrategiesTest {

    @Test
    @DisplayName("The list of registered ids includes the 3 JCA backends")
    void registryIds() {
        assertThat(Ed25519SigningStrategies.registeredIds())
            .contains(Ed25519SigningStrategies.JCA_SUNEC,
                      Ed25519SigningStrategies.CONSCRYPT_BORINGSSL,
                      Ed25519SigningStrategies.BC_JCA);
    }

    @Test
    @DisplayName("createOrDefault with a null/empty id -> returns DEFAULT_ID (conscrypt-boringssl)")
    void defaultsWhenBlank() {
        assertThat(Ed25519SigningStrategies.createOrDefault(null).id())
            .isEqualTo(Ed25519SigningStrategies.DEFAULT_ID);
        assertThat(Ed25519SigningStrategies.createOrDefault("").id())
            .isEqualTo(Ed25519SigningStrategies.DEFAULT_ID);
        assertThat(Ed25519SigningStrategies.createOrDefault("   ").id())
            .isEqualTo(Ed25519SigningStrategies.DEFAULT_ID);
    }

    @Test
    @DisplayName("DEFAULT_ID = conscrypt-boringssl + SAFETY_FALLBACK_ID = jca-sunec")
    void defaultAndSafetyConstants() {
        assertThat(Ed25519SigningStrategies.DEFAULT_ID)
            .isEqualTo(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
        assertThat(Ed25519SigningStrategies.SAFETY_FALLBACK_ID)
            .isEqualTo(Ed25519SigningStrategies.JCA_SUNEC);
    }

    @Test
    @DisplayName("createOrDefault with an invalid id -> falls back to SAFETY_FALLBACK_ID (no exception)")
    void fallbackOnUnknownId() {
        Ed25519SigningStrategy s = Ed25519SigningStrategies.createOrDefault("does-not-exist");
        assertThat(s.id()).isEqualTo(Ed25519SigningStrategies.SAFETY_FALLBACK_ID);
    }

    @Test
    @DisplayName("create(...) with an invalid id -> throws IllegalArgumentException")
    void rawCreateFailsOnUnknown() {
        assertThatThrownBy(() -> Ed25519SigningStrategies.create("nope"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown Ed25519 strategy");
    }
}
