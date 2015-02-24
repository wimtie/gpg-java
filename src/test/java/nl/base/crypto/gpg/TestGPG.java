package nl.base.crypto.gpg;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;

public class TestGPG extends TestCase {

	public void testHaveKey() throws IOException {
		GPG tool = getNewJUnitGPGTool();
		try (InputStream is = JUnitUtil.getResourceInputStream("pubkey.asc")) {
			assertTrue("Key was not successfully imported / haveKey doesn't see it",
					tool.haveKey(tool.getFingerPrint(is)));
		}
		assertFalse("Havekey sees a key that it shouldn't.", tool.haveKey("foobar"));
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

}