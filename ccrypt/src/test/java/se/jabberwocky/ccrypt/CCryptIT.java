package se.jabberwocky.ccrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class CCryptIT {

    private static final String CCRYPT_BINARY = "/usr/local/bin/ccrypt";
    private URL cipherText;

    @Before
    public void setup() {
    }

    @Test
    public void ccrypt_binary() throws IOException,
	    InterruptedException {
	ProcessBuilder builder = new ProcessBuilder(CCRYPT_BINARY, "-V");
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	Process ccrypt = builder.start();
	IOUtils.copy(ccrypt.getInputStream(), buffer);
	ccrypt.waitFor();
	assertEquals("ccrypt exited abnormally", 0, ccrypt.exitValue());
	String output = buffer.toString();
	assertEquals("Unsupported ccrypt version", "ccrypt "
		+ CCryptConstants.CCRYPT_VERSION,
		output.substring(0, "ccrypt 1.10".length()));
    }

    @Test @Ignore
    public void encrypt_file() throws IOException, InterruptedException {
	URL cipherTextURI = getClass().getResource("jabberwocky.txt.cpt");
	assertNotNull(cipherTextURI);

	ProcessBuilder builder = new ProcessBuilder(CCRYPT_BINARY, "--key",
		"through the looking glass", "-m", "-c", "-d", 
		cipherTextURI.getFile());
	
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	Process ccrypt = builder.start();
	IOUtils.copy(ccrypt.getInputStream(), buffer);
	ccrypt.waitFor();
	assertEquals("ccrypt exited abnormally", 0, ccrypt.exitValue());
	String output = buffer.toString();
	System.out.println(output);
    }

    @Test
    public void encrypt_file_and_delete() throws IOException,
	    InvalidKeySpecException, InterruptedException {
	
	URL url = getClass().getResource("jabberwocky.txt");
	assertNotNull(url);
	File plain = File.createTempFile("jabberwocky-", ".txt");
	plain.deleteOnExit();

	File cipher = new File(plain.getAbsolutePath() + ".cpt");

	FileUtils.copyURLToFile(url, plain);

	
	CCrypt cCrypt = new CCrypt("through the looking glass");
	cCrypt.encrypt(plain);

	assertFalse(plain.exists());
	assertTrue(cipher.exists());

	ProcessBuilder builder = new ProcessBuilder(CCRYPT_BINARY, "--key",
		"through the looking glass", "-c", "-m",
		cipher.getAbsolutePath());
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	Process ccrypt = builder.start();
	IOUtils.copy(ccrypt.getInputStream(), buffer);
	IOUtils.copy(ccrypt.getErrorStream(), System.err);
	ccrypt.waitFor();
	
	assertEquals("Wrong exit value", 0, ccrypt.exitValue());


	String output = buffer.toString();
	String plaintext = IOUtils.toString(url);

	System.out.println(output);
	assertEquals(plaintext, output);

	assertEquals("ccrypt exited abnormally", 0, ccrypt.exitValue());

    }
    
    @Test @Ignore
    public void check_magic() throws IOException,
    InvalidKeySpecException, InterruptedException {
	
	URL url = getClass().getResource("jabberwocky.txt");
	assertNotNull(url);
	File plain = File.createTempFile("jabberwocky-", ".txt");
	plain.deleteOnExit();
	
	FileUtils.copyURLToFile(url, plain);
	
	ProcessBuilder builder = new ProcessBuilder(CCRYPT_BINARY, "--key",
		"through the looking glass", "-e", plain.getAbsolutePath());
	
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	Process ccrypt = builder.start();
	IOUtils.copy(ccrypt.getInputStream(), buffer);
	IOUtils.copy(ccrypt.getErrorStream(), System.err);
	ccrypt.waitFor();
	
	assertEquals("Wrong exit value", 0, ccrypt.exitValue());
	
	String output = buffer.toString();
	String plaintext = IOUtils.toString(url);
	
	System.out.println(output);
	assertEquals(plaintext, output);
	
	
    }

}
