package se.jabberwocky.ccrypt.api;

import java.security.spec.InvalidKeySpecException;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.jabberwocky.ccrypt.api.CCryptKey;
import se.jabberwocky.ccrypt.api.CCryptKeyFactory;
import se.jabberwocky.ccrypt.api.CCryptKeySpec;
import static org.junit.Assert.assertNotNull;

public class CCryptKeyFactoryTest {

	private Logger log = LoggerFactory.getLogger(getClass());

	private CCryptKeyFactory keyFactory;
	private CCryptKeySpec keySpec;
	private CCryptKey key;

	@Before
	public void setup() {
		keyFactory = new CCryptKeyFactory();
		keySpec = new CCryptKeySpec("Much ado about nothing!");
	}

	/**
	 * Test method for
	 * {@link se.jabberwocky.ccrypt.api.CCryptKeyFactory#generateKey(se.jabberwocky.ccrypt.api.CCryptKeySpec)}
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
