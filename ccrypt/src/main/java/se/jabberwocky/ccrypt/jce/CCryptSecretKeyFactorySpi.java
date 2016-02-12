package se.jabberwocky.ccrypt.jce;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * <p>
 * Factory for creating CCryptKeys from CCryptKeySpec instances.
 * </p>
 * 
 * <p>
 * <b>This factory implementation is not thread safe!</b>
 * </p>
 */
public class CCryptSecretKeyFactorySpi extends SecretKeyFactorySpi {

	private final RijndaelEngine rijndael;

	public CCryptSecretKeyFactorySpi() {
		this(new RijndaelEngine(256));
	}

	// -- SecretKeyFactorySpi

	public CCryptSecretKeyFactorySpi(RijndaelEngine engine) {
	    this.rijndael = engine;
	}

	/**
	 * <p>
	 * Generate a CCryptKey from a CCryptKeySpec instance.
	 * </p>
	 * 
	 * <p>
	 * <b>This method is not thread safe!</b>
	 * </p>
	 * 
	 * @param spec
	 * @return
	 */
	@Override
	public CCryptKey engineGenerateSecret(KeySpec spec)
			throws InvalidKeySpecException {

		assertCCryptKeySpec(spec);

		CCryptKeySpec cCryptSpec = (CCryptKeySpec) spec;
		rijndael.reset();

		// byte arrays are initialized to 0
		final byte[] key = new byte[32];
		final byte[][] doubleBuffer = new byte[2][32];

		char[] sharedKey = cCryptSpec.getSecret();

		// round of encryption, used for calculate the double buffer index
		int r = 0;
		// double buffer index a and b
		int a = 0, b = 0;
		// shared key index
		int j = 0;

		do {
			for (int i = 0; i < 32; i++) {
				if (j < sharedKey.length) {
					key[i] ^= sharedKey[j++];
				} else {
					break;
				}
			}

			a = r++ % 2; // assign r % 2 to a and increment k by one
			b = r % 2;

			// potentially we could re-use the KeyParameter as the underlying
			// byte array is changed, but rather safe than sorry...
			rijndael.init(true, new KeyParameter(key));
			rijndael.processBlock(doubleBuffer[a], 0, doubleBuffer[b], 0);
		} while (j < sharedKey.length);

		return new CCryptKey(cCryptSpec, doubleBuffer[b]);
	}

	/**
	 * Only supports {@link CCryptKey} instances.
	 */
	@SuppressWarnings("rawtypes")
	@Override
	protected KeySpec engineGetKeySpec(SecretKey key, Class clazz)
			throws InvalidKeySpecException {

		try {
			assertCCryptKey(key);
		} catch (InvalidKeyException e) {
			throw new InvalidKeySpecException(e.getMessage());
		}

		if (clazz.equals(CCryptKeySpec.class)) {
			return ((CCryptKey) key).getSpec();
		} else {
			throw new InvalidKeySpecException();
		}
	}

	/**
	 * Only supports {@link CCryptKey} instances.
	 */
	@Override
	protected SecretKey engineTranslateKey(SecretKey key)
			throws InvalidKeyException {

		assertCCryptKey(key);
		
		return key;
	}

	// -- CCryptSecretKeyFactorySpi

	private void assertCCryptKeySpec(KeySpec keySpec)
			throws InvalidKeySpecException {
		if (!(keySpec instanceof CCryptKeySpec)) {
			throw new InvalidKeySpecException("Only instances of "
					+ CCryptKeySpec.class + " supported!");
		}
	}

	private void assertCCryptKey(SecretKey key) throws InvalidKeyException {
		if (!(key instanceof CCryptKey)) {
			throw new InvalidKeyException("Only instances of "
					+ CCryptKey.class + " supported!");
		}
	}

}
