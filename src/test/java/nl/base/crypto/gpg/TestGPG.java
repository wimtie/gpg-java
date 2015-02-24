package nl.base.crypto.gpg;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;

public class TestGPG extends TestCase {

	public void testGenerateKeys() throws IOException {
		GPG tool = new GPG(File.createTempFile("JUnit", "pkr"), File.createTempFile("JUnit", "skr"));
		try (InputStream is = JUnitUtil.getResourceInputStream("pubkey.asc")) {
			tool.importKey(is);
		}
		try (InputStream is = JUnitUtil.getResourceInputStream("pubkey.asc")) {
			assertTrue("Key was not successfully imported.", tool.haveKey(tool.getFingerPrint(is)));
		}
	}

}