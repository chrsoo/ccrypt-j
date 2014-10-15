package se.jabberwocky.ccrypt;

public interface CCryptConstants {

	/**
	 * Magic number used to match a key with a the IV of a ccrypt file. Seems to
	 * be version dependent
	 */
	public static final byte[] CCRYPT_MAGIC_NUMBER = "c051".getBytes();

	public static final String CCRYPT_VERSION = "1.10";
	public static final double CCRYPT_VERSION_NUMBER = 1.10D;

	// Change to rijndael-256 or similar?
	public static final String CCRYPT_ALGORITHM = "ccrypt";
}
