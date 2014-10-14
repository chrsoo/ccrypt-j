package se.jabberwocky.ccrypt.api;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Decrypts a ccrypt InputStream.
 */
public class CcryptInputStream extends InputStream {

	private final InputStream source;
	private final BufferedBlockCipher blockCipher;
	private byte[] cipherText = new byte[32];
	private byte[] plainText = new byte[32];
	private int index;
	private int bytesInBuffer;

	public CcryptInputStream(InputStream source, CCryptKey key)
			throws IOException {
		this(source, key, new RijndaelEngine(256));
	}

	public CcryptInputStream(InputStream source, CCryptKey key,
			RijndaelEngine rijndael) throws IOException {

		if(rijndael.getBlockSize() != 32) {
			throw new IllegalStateException(
				"CCrypt uses AES 256-bits but currently only " + 
						rijndael.getBlockSize() * 8 + 
						" bits is supported. Please check that unlimited "
						+ "strength encryption has been configured for the "
						+ "Java Runtime environment!");
		}

		this.source = source;

		CFBBlockCipher cfb = new CFBBlockCipher(rijndael, 256);
		blockCipher = new BufferedBlockCipher(cfb);

		// Extract the IV
		CipherParameters keyParam = new KeyParameter(key.getEncoded());
		blockCipher.init(false, keyParam);
		readAndDecryptCipherBlock();
		if (bytesInBuffer < 32) {
			throw new IOException("Could only read " + bytesInBuffer
					+ " bytes from ccrypt InputStream for the "
					+ "Initializing Vector (IV) before end of file was"
					+ "reached, the ccrypt stream should be at least "
					+ "32 bytes long, i.e. the size of the IV");
		}

		byte[] iv = cipherText.clone(); // first 32 bytes of InputStream

		// Initialize cipher with key and IV
		CipherParameters params = new ParametersWithIV(keyParam, iv);
		blockCipher.init(false, params);
		readAndDecryptCipherBlock();
	}

	// -- InputStream

	@Override
	public int read() throws IOException {

		if (index < bytesInBuffer) {
			return plainText[index++];
		}

		if (index == 32) {
			readAndDecryptCipherBlock();
			if (bytesInBuffer == 0) {
				return -1;
			} else {
				return plainText[index++];
			}
		}

		return -1;
	}

	@Override
	public int read(byte[] b) throws IOException {
		if (index < bytesInBuffer) {
			for (int i = 0; i < b.length; i++) {

			}

		}

		return super.read(b);
	}

	// -- CcryptInputStream

	private final void readAndDecryptCipherBlock() throws IOException {
		bytesInBuffer = 0;
		index = 0;
		int len = 0;

		while (len != -1 && bytesInBuffer < 32) {
			len = source.read(cipherText, bytesInBuffer, 32 - bytesInBuffer);
			if (len == -1) {
				break;
			}
			bytesInBuffer += len;
		}

		len = blockCipher.processBytes(cipherText, 0, bytesInBuffer, plainText,
				0);
		if (len < 32) {
			try {
				blockCipher.doFinal(plainText, len);
			} catch (DataLengthException | IllegalStateException
					| InvalidCipherTextException e) {
				throw new IOException("Could not process final byte", e);
			}
		}

	}

}
