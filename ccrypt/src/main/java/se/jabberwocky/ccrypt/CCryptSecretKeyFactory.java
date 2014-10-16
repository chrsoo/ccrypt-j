package se.jabberwocky.ccrypt;

import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import se.jabberwocky.ccrypt.jce.CCryptKeySpec;
import se.jabberwocky.ccrypt.jce.CCryptSecretKeyFactorySpi;

/**
 * Factory for creating a secret key from a shared secret.
 */
public final class CCryptSecretKeyFactory extends CCryptSecretKeyFactorySpi {
	
	/**
	 * <p>
	 * Generate a SecretKey instance from a shared secret
	 * </p>
	 * <p>
	 * <b>This method is not thread safe!</b>
	 * </p>
	 * 
	 * @param secret the shared secret
	 * @return the secret key used by the cipher
	 * @throws InvalidKeySpecException if the key could not be created
	 */
	public SecretKey generateKey(String secret) throws InvalidKeySpecException {
		CCryptKeySpec spec = new CCryptKeySpec(secret);
		return engineGenerateSecret(spec);
	}
}
