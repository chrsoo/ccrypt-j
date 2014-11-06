package se.jabberwocky.ccrypt;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Encrypts an OutputStream
 */
public final class CCryptOutputStream extends OutputStream {

    private final OutputStream sink;
    private final BufferedBlockCipher blockCipher;

    private final byte[] buffer = new byte[64];
    private int index;

    public CCryptOutputStream(SecretKey key, OutputStream sink)
	    throws IOException {
	this(new RijndaelEngine(256), key, sink);
    }

    CCryptOutputStream(RijndaelEngine engine, SecretKey key, OutputStream sink)
	    throws IOException {

	this.sink = sink;

	CFBBlockCipher cfbBlockCipher = new CFBBlockCipher(engine, 256);

	blockCipher = new BufferedBlockCipher(cfbBlockCipher);

	KeyParameter keyParam = new KeyParameter(key.getEncoded());
	byte[] iv = createIV(keyParam);

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

    /*
     * "Assuming that blocks are numbered starting from 0, a special "initial"
     * ciphertext block C[-1] is needed to provide the base case for the above
     * formula. This value C[-1] is called the initialization vector or seed.
     * The seed is chosen at encryption time and written as the first block of
     * the encrypted stream. It is important that the seed is unpredictable; in
     * particular, the same seed should never by used more than once. Otherwise,
     * the two resulting ciphertext blocks C[0] could be related by a simple xor
     * to obtain information about the corresponding plaintext blocks P[0]. If
     * unpredictable seeds are used, CFB is provably as secure as the underlying
     * block cipher.
     * 
     * In ccrypt, the seed is constructed as follows: first, a nonce is
     * contructed by hashing a combination of the host name, current time,
     * process id, and an internal counter into a 28-byte value, using a
     * cryptographic hash function. The nonce is combined with a fixed four-byte
     * "magic number", and the resulting 32-byte value is encrypted by one round
     * of the Rijndael block cipher with the given key. This encrypted block is
     * used as the seed and appended to the beginning of the ciphertext. The use
     * of the magic number allows ccrypt to detect non-matching keys before
     * decryption."
     * 
     * http://ccrypt.sourceforge.net/ccrypt.html
     */
    private byte[] createIV(CipherParameters keyParam) {

	blockCipher.init(true, keyParam);

	byte[] nonce = new byte[32];
	SecureRandom random = new SecureRandom();
	random.nextBytes(nonce);

	// imprint the magic number on the nonce
	for (int i = 0; i < CCryptConstants.CCRYPT_MAGIC_BYTES.length; i++) {
	    nonce[i] = CCryptConstants.CCRYPT_MAGIC_BYTES[i];
	}

	byte[] iv = new byte[32];
	int i = blockCipher.processBytes(nonce, 0, 32, iv, 0);
	if (i != 32) {
	    throw new IllegalStateException("Expected 32 bytes to be "
		    + "encrypted but instead " + i + " bytes were encrypted");
	}

	return iv;
    }

}
