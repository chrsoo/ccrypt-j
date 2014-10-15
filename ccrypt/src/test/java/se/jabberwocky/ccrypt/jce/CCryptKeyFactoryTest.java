package se.jabberwocky.ccrypt.jce;

import java.security.spec.InvalidKeySpecException;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.jabberwocky.ccrypt.jce.CCryptKey;
import se.jabberwocky.ccrypt.jce.CCryptSecretKeyFactorySpi;
import se.jabberwocky.ccrypt.jce.CCryptKeySpec;
import static org.junit.Assert.assertNotNull;

public class CCryptKeyFactoryTest {

	private Logger log = LoggerFactory.getLogger(getClass());

	private CCryptSecretKeyFactorySpi keyFactory;
	private CCryptKeySpec keySpec;
	private CCryptKey key;

	@Before
	public void setup() {
		keyFactory = new CCryptSecretKeyFactorySpi();
		keySpec = new CCryptKeySpec("Much ado about nothing!");
	}

	/**
	 * Test method for
	 * {@link se.jabberwocky.ccrypt.jce.CCryptSecretKeyFactorySpi#generateKey(se.jabberwocky.ccrypt.jce.CCryptKeySpec)}
	 * .
	 * 
	 * @throws InvalidKeySpecException
	 */
	@Test
	public void testGenerateKey() throws InvalidKeySpecException {
		key = keyFactory.engineGenerateSecret(keySpec);
		assertNotNull(key);
		log.debug("CCryptKey: '{}'", key);
	}

}
