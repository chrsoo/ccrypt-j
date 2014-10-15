package se.jabberwocky.ccrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CCryptTest {

	private Logger log = LoggerFactory.getLogger(getClass());

	private SecretKey key;
	private Cipher cipher;
	private byte[] ciphertext;
	private byte[] expected;
	private byte[] actual;

	private CCryptSecretKeyFactory keyFactory;

	@BeforeClass
	public static void addBouncyCastleProvider() {
		// TODO move to configuration files
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setup() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException,
			InvalidKeySpecException {
		
		InputStream in = getClass().getResourceAsStream("jabberwocky.txt.cpt");
		assertNotNull("Ciphertext source cannot be null!", in);
		ciphertext = IOUtils.toByteArray(in);

		in = getClass().getResourceAsStream("jabberwocky.txt");
		assertNotNull("Plaintext source cannot be null!", in);
		expected = IOUtils.toByteArray(in);


		keyFactory = new CCryptSecretKeyFactory();
		key = keyFactory.generateKey("through the looking glass");
	}

	@Test(expected = InvalidAlgorithmParameterException.class)
	public void aes256BitCompliance()
			throws InvalidAlgorithmParameterException, IOException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException {

		cipher = Cipher.getInstance("AES/CFB/NoPadding",
				BouncyCastleProvider.PROVIDER_NAME);
		// ccrypt requires an IV of 32 bytes but AES only supports 16 bytes.
		// Thus a the compliant AES JCE implementation cannot be used. The
		// following method thus provokes an InvalidAlgorithmParameterException
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext,
				0, 32));
	}

	/*
	 * "Assuming that blocks are numbered starting from 0, a special "initial"
	 * ciphertext block C[-1] is needed to provide the base case for the above
	 * formula. This value C[-1] is called the initialization vector or seed.
	 * The seed is chosen at encryption time and written as the first block of
	 * the encrypted stream. It is important that the seed is unpredictable; in
	 * particular, the same seed should never by used more than once. Otherwise,
	 * the two resulting ciphertext blocks C[0] could be related by a simple xor
	 * to obtain information about the corresponding plaintext blocks P[0]. If
	 * unpredictable seeds are used, CFB is provably as secure as the underlying
	 * block cipher.
	 * 
	 * In ccrypt, the seed is constructed as follows: first, a nonce is
	 * contructed by hashing a combination of the host name, current time,
	 * process id, and an internal counter into a 28-byte value, using a
	 * cryptographic hash function. The nonce is combined with a fixed four-byte
	 * "magic number", and the resulting 32-byte value is encrypted by one round
	 * of the Rijndael block cipher with the given key. This encrypted block is
	 * used as the seed and appended to the beginning of the ciphertext. The use
	 * of the magic number allows ccrypt to detect non-matching keys before
	 * decryption."
	 * 
	 * http://ccrypt.sourceforge.net/ccrypt.html
	 * 
	 * "ccrypt is based on the Rijndael block cipher, a version of which was
	 * also chosen by the U.S. government as the Advanced Encryption Standard
	 * (AES, see http://www.nist.gov/aes). This cipher is believed to provide
	 * very strong cryptographic security. ... Stream ciphers operate on data
	 * streams of any length. There are several standard modes for operating a
	 * block cipher as a stream cipher. One such standard is Cipher Feedback
	 * (CFB), defined in NIST Special Publication 800-38A and ANSI X3.106-1983.
	 * ccrypt implements a stream cipher by operating the Rijndael block cipher
	 * in CFB mode."
	 */
	@Test
	public void decrypt_short() throws Exception {
		RijndaelEngine engine = new RijndaelEngine(256);
		CFBBlockCipher cfb = new CFBBlockCipher(engine, 256);

		BufferedBlockCipher blockCipher = new BufferedBlockCipher(cfb);

		// PaddedBufferedBlockCipher blockCipher = new
		// PaddedBufferedBlockCipher(
		// cfb, new ZeroBytePadding());

		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		ParametersWithIV params = new ParametersWithIV(keyParam, ciphertext, 0,
				32);
		blockCipher.init(false, params);

		// first 32 bytes is the IV
		actual = new byte[ciphertext.length - 32];

		int i = blockCipher.processBytes(ciphertext, 32,
				ciphertext.length - 32, actual, 0);
		i += blockCipher.doFinal(actual, i);
		log.info("Copied {} bytes to out", i);

		String actualString = new String(actual);
		String expectedString = new String(expected);

		assertEquals(expectedString, actualString);
	}

	@Test
	public void decrypt_long() throws Exception {
		RijndaelEngine engine = new RijndaelEngine(256);
		CFBBlockCipher cfb = new CFBBlockCipher(engine, 256);

		BufferedBlockCipher blockCipher = new BufferedBlockCipher(cfb);

		// PaddedBufferedBlockCipher blockCipher = new
		// PaddedBufferedBlockCipher(
		// cfb, new ZeroBytePadding());

		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		ParametersWithIV params = new ParametersWithIV(keyParam, ciphertext, 0,
				32);
		blockCipher.init(false, params);

		// first 32 bytes is the IV
		actual = new byte[ciphertext.length - 32];

		int i = blockCipher.processBytes(ciphertext, 32,
				ciphertext.length - 32, actual, 0);
		i += blockCipher.doFinal(actual, i);
		log.info("Copied {} bytes to out", i);

		String actualString = new String(actual);
		String expectedString = new String(expected);

		assertEquals(expectedString, actualString);
	}

	@Test
	public void decrypt_iterating() throws Exception {
		
		RijndaelEngine engine = new RijndaelEngine(256);
		CFBBlockCipher cfb = new CFBBlockCipher(engine, 256);

		BufferedBlockCipher blockCipher = new BufferedBlockCipher(cfb);

		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		ParametersWithIV params = new ParametersWithIV(keyParam, ciphertext, 0,
				32);
		blockCipher.init(false, params);

		// first 32 bytes is the IV
		actual = new byte[ciphertext.length - 32];

		int j = 0, len;

		log.info("Ciphertext: {}; actual {}", ciphertext.length, actual.length);
		for (int i = 32; i < ciphertext.length; i += 32) {
			len = ciphertext.length - i;
			len = len > 32 ? 32 : len;
			len = blockCipher.processBytes(ciphertext, i, len, actual, j);
			log.debug("pos: {}; len: {}", i, len);
			j += len;
		}

		j += blockCipher.doFinal(actual, j);
		log.info("Copied {} bytes to out", j);

		String actualString = new String(actual);
		String expectedString = new String(expected);

		assertEquals(expectedString, actualString);
	}

	@Test
	@Ignore("TODO: Implement a test with a key that surpasses 32 bytes")
	public void decrypt_veryLongKey() {

	}

	@Test
	public void checkUnlimitedStrength() throws NoSuchAlgorithmException {
		log.info("Max allowed key length is {} bits for AES",
				Cipher.getMaxAllowedKeyLength("AES"));
		assertFalse("Unlimited cryptographic strength unavailable",
				Cipher.getMaxAllowedKeyLength("AES") < 256);
	}

}