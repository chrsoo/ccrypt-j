package se.jabberwocky.ccrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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

import se.jabberwocky.ccrypt.jce.CCryptKeySpec;
import se.jabberwocky.ccrypt.jce.CCryptSecretKeyFactorySpi;

public class CCryptInputStreamTest {

    private SecretKey key;
    private byte[] expected;
    private byte[] actual;
    private CCryptSecretKeyFactorySpi keyFactory;

    @Before
    public void setup() throws NoSuchAlgorithmException,
	    NoSuchProviderException, NoSuchPaddingException, IOException,
	    InvalidKeySpecException {

	keyFactory = new CCryptSecretKeyFactorySpi();
	CCryptKeySpec spec = new CCryptKeySpec("through the looking glass");
	key = keyFactory.engineGenerateSecret(spec);

	InputStream in = getClass().getResourceAsStream("jabberwocky.txt");
	assertNotNull("Plaintext source cannot be null!", in);
	expected = IOUtils.toByteArray(in);
    }

    @Test
    public void test() throws IOException {
	InputStream in = getClass().getResourceAsStream("jabberwocky.txt.cpt");
	assertNotNull("Ciphertext source cannot be null!", in);
	// TODO test with magic number validation
	CCryptInputStream ccryptStream = new CCryptInputStream(key, in, false);
	actual = IOUtils.toByteArray(ccryptStream);

	String actualString = new String(actual);
	String expectedString = new String(expected);

	assertEquals(expectedString.length(), actualString.length());
	assertEquals(expectedString, actualString);
    }

}