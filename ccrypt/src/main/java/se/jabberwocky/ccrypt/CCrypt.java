package se.jabberwocky.ccrypt;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.crypto.engines.RijndaelEngine;

import se.jabberwocky.ccrypt.jce.CCryptKey;
import se.jabberwocky.ccrypt.jce.CCryptKeySpec;
import se.jabberwocky.ccrypt.jce.CCryptSecretKeyFactorySpi;

/**
 * <p>
 * CCrypt Utility class for generating CCRypt secret keys and
 * encrypting/decrypting files. The class IS NOT thread safe as it re-uses the
 * stateful Rijndael crypographic engine.
 * </p>
 * <p>
 * <p>
 * From the ccrypt documentation:
 * </p>
 * <p>
 * <blockquote> ccrypt is based on the Rijndael block cipher, a version of which
 * was also chosen by the U.S. government as the Advanced Encryption Standard
 * (AES, see http://www.nist.gov/aes). This cipher is believed to provide very
 * strong cryptographic security. ... Stream ciphers operate on data streams of
 * any length. There are several standard modes for operating a block cipher as
 * a stream cipher. One such standard is Cipher Feedback (CFB), defined in NIST
 * Special Publication 800-38A and ANSI X3.106-1983. ccrypt implements a stream
 * cipher by operating the Rijndael block cipher in CFB mode. </blockquote>
 */
public final class CCrypt {

    private final RijndaelEngine engine;
    private final CCryptKey secret;

    /**
     * <p>
     * Create a new CCrypt instance with the secret in the form of a String.
     * </p>
     * <p>
     * <p>
     * Please note that the {@link #CCrypt(char[])} constructor is probably
     * safer to use, assuming the argument supplied to the constructor is
     * properly erased before discarding!
     * </p>
     *
     * @param secret the shared secret
     * @throws InvalidKeySpecException if the key could not be created
     */
    public CCrypt(String secret) throws InvalidKeySpecException {
        this(new CCryptKeySpec(secret));
    }

    /**
     * <p>
     * Create a new CCrypt instance with the secret in the form of a String.
     * </p>
     *
     * @param secret the shared secret
     * @return the secret key used by the cipher
     * @throws InvalidKeySpecException if the key could not be created
     */
    public CCrypt(char[] secret) throws InvalidKeySpecException {
        this(new CCryptKeySpec(secret));
    }

    /**
     * <p>
     * Create a new CCrypt instance based on the Secret
     * </p>
     *
     * @param spec The Secret KeySpecification
     * @throws InvalidKeySpecException If the Secret cannot be generated from the KeySpec
     */
    private CCrypt(CCryptKeySpec spec) throws InvalidKeySpecException {

        engine = new RijndaelEngine(256);
        CCryptSecretKeyFactorySpi keyFactory =
                new CCryptSecretKeyFactorySpi(engine);

        this.secret = keyFactory.engineGenerateSecret(spec);
    }

    /**
     * Encrypt a plain text and and delete the original. The new file name is
     * identical to the source with the <code>.cpt</code> suffix appended.
     *
     * @param plain the plain text file to encrypt
     * @throws IOException if there is a problem encrypting the plain text file
     */
    public void encrypt(File plain) throws IOException {
        File cipher = new File(plain.getAbsolutePath() + ".cpt");
        encrypt(plain, cipher);
        plain.delete();
    }

    /**
     * Encrypt a file while retaining the original.
     *
     * @param plain the plain text file to encrypt
     * @throws IOException if there is a problem encrypting the plain text file
     */
    public void encrypt(File plain, File cipher)
            throws IOException {
        try (FileInputStream in = new FileInputStream(plain);
             CCryptOutputStream out = new CCryptOutputStream(engine, secret,
                     new FileOutputStream(cipher))) {
            IOUtils.copy(in, out);
        }
    }

    /**
     * Decrypt a cipher file and remove the <code>.cpt</code> suffix, if
     * present.
     *
     * @param cipher the encrypted file to decipher
     * @throws IOException if there is a problem decrypting the cipher text file or
     *                     writing the plain text file
     */
    public void decrypt(File cipher) throws IOException
    {

        decrypt(cipher, false);

    }

    /**
     * Decrypt a cipher file and remove the <code>.cpt</code> suffix, if
     * present.
     *
     * @param cipher the encrypted file to decipher
     * @param verify true if the key matches the key used for encryption
     * @throws IOException if there is a problem decrypting the cipher text file or
     *                     writing the plain text file
     */
    public void decrypt(File cipher, boolean verify) throws IOException {

        File temp = File.createTempFile(cipher.getName(), ".tmp");

        decrypt(cipher, temp, verify);

        String filename = cipher.getAbsolutePath();
        if (filename.endsWith(".cpt")) {
            filename = filename.substring(0,
                    filename.length() - ".cpt".length());
        }
        cipher.delete();
        File plain = new File(filename);
        temp.renameTo(plain);
    }

    /**
     * Decrypt a cipher file to a plain text file.
     *
     * @param cipher the encrypted file to decipher
     * @param plain  the name of the plain text file
     * @throws FileNotFoundException if the cipher file cannot be found
     * @throws IOException           if there is a problem decrypting the cipher text file or
     *                               writing the plain text file
     */
    public void decrypt(File cipher, File plain) throws IOException {

        decrypt(cipher, plain, false);

    }

    /**
     * Decrypt a cipher file to a plain text file.
     *
     * @param cipher the encrypted file to decipher
     * @param plain  the name of the plain text file
     * @param verify true if the key matches the key used for encryption
     * @throws FileNotFoundException if the cipher file cannot be found
     * @throws IOException           if there is a problem decrypting the cipher text file or
     *                               writing the plain text file
     */
    public void decrypt(File cipher, File plain, boolean verify) throws IOException {

        try
        (
            CCryptInputStream in = new CCryptInputStream(engine, secret, new FileInputStream(cipher), verify);
            FileOutputStream out = new FileOutputStream(plain)
        ) {

            IOUtils.copy(in, out);

        }
    }

    public byte[] toCipher(byte[] plain) throws IOException {

        byte[] bytes;

        try (
            ByteArrayInputStream input = new ByteArrayInputStream(plain);
            ByteArrayOutputStream cipher = new ByteArrayOutputStream();
            CCryptOutputStream output = new CCryptOutputStream(engine, secret, cipher)
        ) {

            IOUtils.copy(input, output);
            output.close();
            output.flush();
            bytes = cipher.toByteArray();
        }
        return bytes;
    }

    public byte[] toPlain(byte[] cipher) throws IOException {

        byte[] bytes;

        try (
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ByteArrayInputStream plain = new ByteArrayInputStream(cipher);
            CCryptInputStream input = new CCryptInputStream(engine, secret, plain, true)
        ) {

            IOUtils.copy(input, output);
            bytes = output.toByteArray();

        }
        return bytes;

    }
}