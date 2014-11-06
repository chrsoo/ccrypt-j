package se.jabberwocky.ccrypt.jce;

import java.security.spec.KeySpec;
import java.util.Arrays;

import se.jabberwocky.ccrypt.CCryptConstants;

public final class CCryptKeySpec implements KeySpec {

	private final char[] secret;

	/**
	 * <p>Creates a secret key out of a char array. A copy of the array is 
	 * stored in the secret key and the caller should dispose of the char array 
	 * by erasing its content before letting go of the argument supplied in the
	 * constructor, e.g. by filling it with a dummy character:<p>
	 * <blockquote>
	 * <code>Arrays.fill(secret, '*');</code>
	 * </blockquote>
	 * @param secret the secret shared between the encryptor and the decryptor.
	 */
	public CCryptKeySpec(char[] secret) {
		this.secret = secret.clone();
	}
	
	/**
	 * <p>Create a secret from a String representation.</p>
	 * <p>Please note that the {@link #CCryptKeySpec(char[])} constructor is 
	 * probably safer to use, assuming the argument supplied to the constructor
	 * is properly erased before discarding!</p>
	 * @param secret
	 */
	public CCryptKeySpec(String secret) {
		if(secret == null || secret.trim().isEmpty()) {
			throw new IllegalArgumentException("The shared key must not be blank");
		}
		this.secret = secret.trim().toCharArray();
	}
	
	/**
	 * Get the key as a newly created char array.
	 * 
	 * @return a newly created char array
	 */
	char[] getSecret() {
		return secret;
	}

	String getAlgorithm() {
		return CCryptConstants.CCRYPT_ALGORITHM;
	}

	// -- Object

	@Override
	public String toString() {
		return "[algorithm: '" + CCryptConstants.CCRYPT_ALGORITHM
				+ "'; secret: <undisclosed>]";
	}
	
	@Override
	protected void finalize() throws Throwable {
		// "burn after reading"
		Arrays.fill(secret, '*');
		super.finalize();
	}

}
