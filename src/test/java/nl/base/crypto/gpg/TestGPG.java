package nl.base.crypto.gpg;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import junit.framework.TestCase;

import org.apache.commons.io.IOUtils;

public class TestGPG extends TestCase {

	private static final String JUNIT_PASSPHRASE = "JUnitPassphrase";

	public void testHaveKey() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		try (InputStream is = JUnitUtil.getResourceInputStream("pubkey.asc")) {
			assertTrue("Key was not successfully imported / haveKey doesn't see it",
					tool.havePublicKey(tool.getFingerPrint(is)));
		}
		assertFalse("Havekey sees a key that it shouldn't.", tool.havePublicKey("foobar"));
	}

	public void testEncrypt() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		File cipherTmp = File.createTempFile("JUnit", ".gpg");
		tool.encrypt(new ByteArrayInputStream("this is cleartext".getBytes()), cipherTmp,
				getJunitKeyringFingerPrint(tool));
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

	/**
	 *
	 * Utility method to get a GPG instance with clean keyrings.
	 *
	 * 	@return GPG instance with default JUnit keyrings imported
	 */
	private GPG getNewJUnitGPGTool() {
		try (InputStream pkis = JUnitUtil.getResourceInputStream("pubkey.asc");
				InputStream skis = JUnitUtil.getResourceInputStream("seckey.asc")) {
			GPG tool = new GPG(File.createTempFile("JUnit", "pkr"), File.createTempFile("JUnit", "skr"));
			tool.importKey(pkis);
			tool.importKey(skis);
			return tool;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private String getJunitKeyringFingerPrint(GPG gpg) {
		try (InputStream pkis = JUnitUtil.getResourceInputStream("pubkey.asc")) {
			return gpg.getFingerPrint(pkis);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}