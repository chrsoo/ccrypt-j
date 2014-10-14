package se.jabberwocky.ccrypt.api;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class CcryptOutputStream extends OutputStream {

	private final OutputStream sink;
	private final BufferedBlockCipher blockCipher;

	private final byte[] buffer = new byte[64];
	private int index;

	public CcryptOutputStream(OutputStream sink, CCryptKey key,
			RijndaelEngine rijndael) throws IOException {

		if(rijndael.getBlockSize() != 32) {
			throw new IllegalStateException(
				"CCrypt uses AES 256-bits but currently only " + 
						rijndael.getBlockSize() * 8 + 
						" bits is supported. Please check that unlimited "
						+ "strength encryption has been configured for the "
						+ "Java Runtime environment!");
		}

		this.sink = sink;

		CFBBlockCipher cfbBlockCipher = new CFBBlockCipher(rijndael, 256);

		blockCipher = new BufferedBlockCipher(cfbBlockCipher);

		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		blockCipher.init(true, keyParam);
		byte[] iv = createIV();

		CipherParameters params = new ParametersWithIV(keyParam, iv);
		blockCipher.init(true, params);

		sink.write(iv);
		index = 0;
	}

	// -- OutputStream

	@Override
	public void write(int b) throws IOException {
		index += blockCipher.processByte((byte) b, buffer, index);
		if (index == buffer.length) {
			flush();
		} else if (index > buffer.length) {
			throw new IllegalStateException("Cipher buffer overflow, "
					+ "buffer size must not exceed block size of 32 bytes "
					+ "but was " + index);
		}
	}

	/**
	 * </p>Flushes the encrypted bytes to the underlying OutputStream</p>
	 * <p>
	 * <b>WARNING due to how the CFB block cipher works there may be unencrypted
	 * bytes still remaining in the buffer, even after the flush! </b>
	 * </p>
	 */
	@Override
	public void flush() throws IOException {
		if (index > 0) {
			sink.write(buffer, 0, index);
			index = 0;
		}
		sink.flush();
	}

	@Override
	public void close() throws IOException {
		super.close();
		try {
			index += blockCipher.doFinal(buffer, index);
			sink.write(buffer, 0, index);
		} catch (DataLengthException | IllegalStateException
				| InvalidCipherTextException e) {
			throw new IOException("Could not write the final bytes of "
					+ "ciphertext", e);
		} finally {
			sink.close();
		}

	}

	private byte[] createIV() {

		byte[] nonce = new byte[32];
		SecureRandom random = new SecureRandom();
		random.nextBytes(nonce);

		for (int i = 0; i < CCryptConstants.CCRYPT_MAGIC_NUMBER.length; i++) {
			nonce[i] = CCryptConstants.CCRYPT_MAGIC_NUMBER[i];
		}

		byte[] iv = new byte[32];
		blockCipher.processBytes(nonce, 0, 32, iv, 0);

		return iv;
	}

}
