package se.jabberwocky.ccrypt.api;

import java.security.spec.KeySpec;

public class CCryptKeySpec implements KeySpec {

	private final String sharedKey;

	public CCryptKeySpec(String sharedKey) {
		if(sharedKey == null || sharedKey.trim().isEmpty()) {
			throw new IllegalArgumentException("The shared key must not be blank");
		}
		this.sharedKey = sharedKey.trim();
	}

	/**
	 * Get the key as a newly created char array.
	 * 
	 * @return a newly created char array
	 */
	char[] getSharedKey() {
		return sharedKey.toCharArray();
	}

	String getAlgorithm() {
		return CCryptConstants.CCRYPT_ALGORITHM;
	}

	// -- Object

	@Override
	public String toString() {
		return "[algorithm: '" + CCryptConstants.CCRYPT_ALGORITHM
				+ "; sharedKey: '" + new String(sharedKey) + "']";
	}

}
