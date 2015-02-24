package nl.base.crypto.gpg;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * Simple utility class to parse output of --list-keys and its ilk. This is useful for debugging.
 *
 */
final class GPGKeyListParser {

	private static final Pattern PUB_PATTERN = Pattern.compile("^(pub|sec)\\s+([0-9]+[A-Z]{1})/([A-F0-9]{8})\\s+"
			+ "([0-9]{4}-[0-9]{2}-[0-9]{2}$)");
	private static final Pattern FP_PATTERN = Pattern.compile("^\\s+Key fingerprint = ([A-F0-9 ]+)$");
	private static final Pattern UID_PATTERN = Pattern.compile("^uid\\s+(.*)$");
	private static final Pattern SUB_PATTERN = Pattern.compile("^sub\\s+([0-9]+[A-Z]{1})/([A-F0-9]{8})\\s+"
			+ "([0-9]{4}-[0-9]{2}-[0-9]{2}$)");


	public static List<GPGKeyInfo> parse(String gpgOutput) {
		List<GPGKeyInfo> list = new ArrayList<>();
		BufferedReader reader = new BufferedReader(new StringReader(gpgOutput));
		GPGKeyInfo key;
		try {
			reader.readLine(); // dismiss filename
			reader.readLine(); // dismiss ---------------
			while ((key = parseGPGKeyInfo(reader)) != null) {
				list.add(key);
			}
			return list;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}
	}

	private static GPGKeyInfo parseGPGKeyInfo(BufferedReader reader) throws IOException {
		String line = reader.readLine(); // dismiss path
		if (line == null) {
			return null;
		}
		Matcher m = getMatched(PUB_PATTERN, line);
		String pubSec = m.group(1);
		String keyType = m.group(2);
		String whatsThis = m.group(3);
		String created = m.group(4);
		line = reader.readLine();
		m = getMatched(FP_PATTERN, line);
		String fingerPrint = m.group(1).replaceAll("\\s", "");
		line = reader.readLine();
		m = getMatched(UID_PATTERN, line);
		String uid = m.group(1);
		line = reader.readLine();
		//TODO: fix subkeys.
		/*if ((m = getMatched(SUB_PATTERN, line)) != null) {
		}*/
		while (!(line = reader.readLine()).equals("")) {
			// Read remaining lines of this key.
		}
		return new GPGKeyInfo(pubSec, fingerPrint, keyType, whatsThis, created, uid);
	}

	/**
	 * get matcher or crash on invalid input.
	 *
	 * @param reader
	 * @return a matcher to find our fields.
	 * @throws IOException
	 */
	private static Matcher getMatched(Pattern p, String line)
			throws IOException {
		if (line == null) {
			return null;
		}
		Matcher m = p.matcher(line);
		if (!m.matches()) {
			throw new IllegalStateException("Invalid GPG output: " + line);
		}
		return m;
	}


	public static final class GPGKeyInfo {

		private final String fingerPrint;
		private final String keyType;
		private final String whatsThis;
		private final String created;
		private final String uid;
		private final String pubSec;

		public GPGKeyInfo(String pubSec, String fingerPrint, String keyType, String whatsThis,
				String created, String uid) {
			this.pubSec = pubSec;
			this.fingerPrint = fingerPrint;
			this.keyType = keyType;
			this.whatsThis = whatsThis;
			this.created = created;
			this.uid = uid;
		}

	}

}