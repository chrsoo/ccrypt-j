package se.jabberwocky.ccrypt;

import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * The Rijndael 256-bit key used in the CCrypt implementation of the AES/CFB
 * crypto.
 */
public final class CCryptKey implements SecretKey {

	private static final long serialVersionUID = 1L;

	private final byte[] key;
	private final CCryptKeySpec spec;

	/**
	 * Copies the key into a new byte array to prevent inadvert manipulation.
	 * 
	 * @param spec
	 *            the key specification from whence this CCrypt key was derived
	 * @param key
	 *            256 bit key stored as a 32 byte array
	 */
	CCryptKey(CCryptKeySpec spec, byte[] key) {

		if(key.length != 32) {
			throw new IllegalArgumentException("CCrypt keys must be 256 bits");
		}

		this.spec = spec;
		this.key = Arrays.copyOf(key, key.length);
	}

	@Override
	public String getAlgorithm() {
		return spec.getAlgorithm();
	}

	@Override
	public String getFormat() {
		// no ASN.1 format supported
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return key;
	}

	CCryptKeySpec getSpec() {
		return spec;
	}

	// Object

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("[");
		builder.append(spec);
		builder.append("; key: ");
		String separator = "";
		for (int i = 0; i < key.length; i++) {
			builder.append(key[i]);
			builder.append(separator);
			separator = ",";
		}
		builder.append("]");
		return builder.toString();
	}
}
