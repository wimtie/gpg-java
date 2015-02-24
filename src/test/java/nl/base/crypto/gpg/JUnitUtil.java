package nl.base.crypto.gpg;

import java.io.InputStream;

public class JUnitUtil {

	private JUnitUtil() {} // Util class

	public static InputStream getResourceInputStream(String resourceName) {
		ClassLoader cl = JUnitUtil.class.getClassLoader();
		return cl.getResourceAsStream(resourceName);
	}

}
