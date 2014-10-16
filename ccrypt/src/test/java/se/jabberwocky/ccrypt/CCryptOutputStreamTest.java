package se.jabberwocky.ccrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class CCryptOutputStreamTest {

	private SecretKey key;
	private byte[] expected;
	private byte[] actual;
	private CCryptSecretKeyFactory keyFactory;

	@Before
	public void setup() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException,
			InvalidKeySpecException {

		keyFactory = new CCryptSecretKeyFactory();
		key = keyFactory.generateKey("through the looking glass");

		InputStream in = getClass().getResourceAsStream("jabberwocky.txt");
		assertNotNull("Plaintext source cannot be null!", in);
		expected = IOUtils.toByteArray(in);
	}

	@Test
	public void encrypt_decrypt() throws IOException {

		ByteArrayOutputStream outbuffer = new ByteArrayOutputStream();
		CCryptOutputStream output = new CCryptOutputStream(outbuffer, key);

		IOUtils.write(expected, output);
		output.close();
		byte[] ciphertext = outbuffer.toByteArray();

		assertEquals("Ciphertext should be the same length as the plaintext "
				+ "plus 32 bytes", expected.length + 32, ciphertext.length);

		ByteArrayInputStream inbuffer = new ByteArrayInputStream(ciphertext);
		CCryptInputStream input = new CCryptInputStream(inbuffer, key);

		actual = IOUtils.toByteArray(input);

		String actualString = new String(actual);
		String expectedString = new String(expected);

		assertEquals(expectedString.length(), actualString.length());
		assertEquals(expectedString, actualString);
	}

}