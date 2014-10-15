package se.jabberwocky.ccrypt.jce;

import java.security.Provider;

public final class CCryptProvider extends Provider {

	private static final long serialVersionUID = 1L;

	public static final String PROVIDER_NAME = "ccrypt";
	public static final double PROVIDER_VERSION = CCryptConstants.CCRYPT_VERSION_NUMBER;
	public static final String PROVIDER_INFO = "http://ccrypt.sourceforge.net/";

	public CCryptProvider() {
		// For this provider to work with JCE it has to be part of a signed JAR
		// etc. Please refer to
		// http://www.cs.mun.ca/java-api-1.5/guide/security/jce/HowToImplAJCEProvider.html
		// TODO setup JAR signing in Maven POM
		super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

		put("SecretKeyFactory." + CCryptConstants.CCRYPT_ALGORITHM,
				CCryptSecretKeyFactorySpi.class.getName());
	}

}
