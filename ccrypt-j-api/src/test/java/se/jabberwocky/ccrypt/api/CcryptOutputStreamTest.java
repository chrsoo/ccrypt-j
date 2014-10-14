package se.jabberwocky.ccrypt.api;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.junit.Before;
import org.junit.Test;

import se.jabberwocky.ccrypt.api.CCryptKey;
import se.jabberwocky.ccrypt.api.CCryptKeyFactory;
import se.jabberwocky.ccrypt.api.CCryptKeySpec;
import se.jabberwocky.ccrypt.api.CcryptInputStream;
import se.jabberwocky.ccrypt.api.CcryptOutputStream;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CcryptOutputStreamTest {

	private RijndaelEngine engine;
	private CCryptKeySpec keySpec;
	private CCryptKey key;
	private byte[] expected;
	private byte[] actual;
	private CCryptKeyFactory keyFactory;

	@Before
	public void setup() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException,
			InvalidKeySpecException {

		engine = new RijndaelEngine(256);
		keyFactory = new CCryptKeyFactory(engine);
		keySpec = new CCryptKeySpec("through the looking glass");
		key = keyFactory.engineGenerateSecret(keySpec);

		InputStream in = getClass().getResourceAsStream("jabberwocky.txt");
		assertNotNull("Plaintext source cannot be null!", in);
		expected = IOUtils.toByteArray(in);
	}

	@Test
	public void encrypt_decrypt() throws IOException {

		ByteArrayOutputStream outbuffer = new ByteArrayOutputStream();
		CcryptOutputStream output = new CcryptOutputStream(outbuffer, key,
				engine);

		IOUtils.write(expected, output);
		output.close();
		byte[] ciphertext = outbuffer.toByteArray();

		assertEquals("Ciphertext should be the same length as the plaintext "
				+ "plus 32 bytes", expected.length + 32, ciphertext.length);

		ByteArrayInputStream inbuffer = new ByteArrayInputStream(ciphertext);
		CcryptInputStream input = new CcryptInputStream(inbuffer, key);

		actual = IOUtils.toByteArray(input);

		// System.out.println(ciphertext.toString());

		String actualString = new String(actual);
		String expectedString = new String(expected);

		// assertEquals(expectedString.length(), actualString.length());
		assertEquals(expectedString, actualString);
	}

}