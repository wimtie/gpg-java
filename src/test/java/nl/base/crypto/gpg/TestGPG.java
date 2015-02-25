package nl.base.crypto.gpg;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import junit.framework.TestCase;
import nl.base.crypto.gpg.GPG.GPGException;

import org.apache.commons.io.IOUtils;

public class TestGPG extends TestCase {

	private static final String SECKEY_ASC_RESOURCE_FILENAME = "seckey.asc";
	private static final String PUBKEY_ASC_RESOURCE_FILENAME = "pubkey.asc";
	private static final String JUNIT_PASSPHRASE = "JUnitPassphrase";
	private static final String JUNIT_KEYPAIR_FINGERPRINT = "AB98FD9C260FD9F4E323BB8E1084E2961A0D3FC6";

	public void testHaveKey() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		try (InputStream is = JUnitUtil.getResourceInputStream(PUBKEY_ASC_RESOURCE_FILENAME)) {
			assertTrue("Key was not successfully imported / haveKey doesn't see it",
					tool.havePublicKey(tool.getFingerPrint(is)));
		}
		assertFalse("haveKey() sees a key that it shouldn't.", tool.havePublicKey("foobar"));
	}

	public void testEncrypt() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		File cipherTmp = File.createTempFile("JUnit", ".gpg");
		tool.encrypt(new ByteArrayInputStream("this is cleartext".getBytes()), cipherTmp,
				JUNIT_KEYPAIR_FINGERPRINT);
		String actual = new String(Files.readAllBytes(cipherTmp.toPath()));
		assertNotSame("cleartext not encrypted", "this is cleartext", actual);
	}

	public void testDecrypt() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		InputStream decryptStream = tool.decrypt(
				JUnitUtil.getResourceInputStream("gpgencrypted.gpg"), JUNIT_PASSPHRASE);
		assertEquals("Decrypt failed.", "this is a statically encrypted resource for JUnit testing\n",
				IOUtils.toString(decryptStream));
	}

	public void testEncryptDecrypt() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		String testString = "Testing testing, is this thing on?";
		InputStream cipherText = tool.encrypt(testString.getBytes(),
				JUNIT_KEYPAIR_FINGERPRINT);
		assertEquals(testString, IOUtils.toString(tool.decrypt(cipherText, JUNIT_PASSPHRASE)));
	}

	public void testDeleteKey() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		try {
			tool.deletePublicKey(JUNIT_KEYPAIR_FINGERPRINT);
			throw new IllegalStateException("deletePublicKey should have thrown an error, but it didn't");
		} catch (GPGException e) {
			if(!e.getMessage().contains("gpg: there is a secret key for public key")) {
				throw new IllegalStateException("Wrong exception", e);
			}
		}
		tool.deleteSecretKey(JUNIT_KEYPAIR_FINGERPRINT);
		// Now we should be allowed to delete public key
		tool.deletePublicKey(JUNIT_KEYPAIR_FINGERPRINT);
		assertFalse("Still have key after delete", tool.havePublicKey(JUNIT_KEYPAIR_FINGERPRINT));
	}

	public void testSign() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		InputStream is = tool.sign("This message wants to be signed".getBytes(),
				JUNIT_KEYPAIR_FINGERPRINT, JUNIT_PASSPHRASE);
		String res = IOUtils.toString(is);
		assertTrue("Is not a clearsigned string", res.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"));
		assertTrue("Is not our clearsigned string", res.contains("This message wants to be signed"));
		assertTrue("Has no signature", res.contains("-----BEGIN PGP SIGNATURE-----"));
	}

	public void testVerifySignature() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		InputStream is = JUnitUtil.getResourceInputStream("signed.gpg");
		assertTrue("Not verified!", tool.verifySignature(new File("/tmp/signed.gpg")));
		assertTrue("Not verified!", tool.verifySignature(is));
	}

	public void testSignAndVerify() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		InputStream is = tool.sign("This message wants to be signed".getBytes(),
				JUNIT_KEYPAIR_FINGERPRINT, JUNIT_PASSPHRASE);
		assertTrue("Verify failed on own signature.", tool.verifySignature(is));
	}

	public void testGetFingerPrint() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		assertEquals(JUNIT_KEYPAIR_FINGERPRINT,
				tool.getFingerPrint(JUnitUtil.getResourceInputStream(PUBKEY_ASC_RESOURCE_FILENAME)));
	}

	/**
	 *
	 * Utility method to get a GPG instance with clean keyrings.
	 *
	 * 	@return GPG instance with default JUnit keyrings imported
	 */
	private GPG getNewJUnitGPGTool() {
		try (InputStream pkis = JUnitUtil.getResourceInputStream(PUBKEY_ASC_RESOURCE_FILENAME);
				InputStream skis = JUnitUtil.getResourceInputStream(SECKEY_ASC_RESOURCE_FILENAME)) {
			GPG tool = new GPG(File.createTempFile("junit", ".pkr"), File.createTempFile("junit", ".skr"));
			tool.importKey(pkis);
			tool.importKey(skis);
			return tool;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}