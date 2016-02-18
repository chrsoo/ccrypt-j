package se.jabberwocky.ccrypt.jce;

import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

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

		int length = secret.length;
		while(length%32 != 0)length++;
		char[] padded = new char[length];
		Arrays.fill(padded, (char)0);
		for(int i = 0; i< secret.length; i++)
			padded[i] = secret[i];
		this.secret = padded;
	}
	
	/**
	 * <p>Create a secret from a String representation.</p>
	 * <p>Please note that the {@link #CCryptKeySpec(char[])} constructor is 
	 * probably safer to use, assuming the argument supplied to the constructor
	 * is properly erased before discarding!</p>
	 * @param secret
	 */
	public CCryptKeySpec(String secret) {
		this(secret.trim().toCharArray());
		if(secret == null || secret.trim().isEmpty()) {
			throw new IllegalArgumentException("The shared key must not be blank");
		}
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
