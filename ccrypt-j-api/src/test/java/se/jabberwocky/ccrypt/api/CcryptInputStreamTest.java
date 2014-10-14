package se.jabberwocky.ccrypt.api;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import se.jabberwocky.ccrypt.api.CCryptKey;
import se.jabberwocky.ccrypt.api.CCryptKeyFactory;
import se.jabberwocky.ccrypt.api.CCryptKeySpec;
import se.jabberwocky.ccrypt.api.CcryptInputStream;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CcryptInputStreamTest {

	private CCryptKeySpec keySpec;
	private CCryptKey key;
	private byte[] expected;
	private byte[] actual;
	private CCryptKeyFactory keyFactory;

	@Before
	public void setup() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException,
			InvalidKeySpecException {

		keyFactory = new CCryptKeyFactory();
		keySpec = new CCryptKeySpec("through the looking glass");
		key = keyFactory.engineGenerateSecret(keySpec);

		InputStream in = getClass().getResourceAsStream("jabberwocky.txt");
		assertNotNull("Plaintext source cannot be null!", in);
		expected = IOUtils.toByteArray(in);
	}

	@Test
	public void test() throws IOException {
		InputStream in = getClass().getResourceAsStream("jabberwocky.txt.cpt");
		assertNotNull("Ciphertext source cannot be null!", in);
		CcryptInputStream ccryptStream = new CcryptInputStream(in, key);
		actual = IOUtils.toByteArray(ccryptStream);

		String actualString = new String(actual);
		String expectedString = new String(expected);

		assertEquals(expectedString.length(), actualString.length());
		assertEquals(expectedString, actualString);
	}

}