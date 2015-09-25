package nl.base.crypto.gpg;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import nl.base.crypto.gpg.GPGKeyListParser.GPGKeyInfo;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Thin Java wrapper for GPG command line tool.
 *
 */
public class GPG {

	private static final Logger log = LoggerFactory.getLogger(GPG.class);

	private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("\\s*Key fingerprint = ([A-F0-9 ]*).*",
			Pattern.MULTILINE);

	private final String version;
	private File publicKeyRingFile = null;
	private File secretKeyRingFile = null;

	private TrustModel trustModel = null;

	public enum TrustModel {

		PGP("pgp"),
		CLASSIC("classic"),
		DIRECT("direct"),
		ALWAYS("always"),
		AUTO("auto");

		private final String option;

		private TrustModel(String option) {
			this.option = option;
		}

		public String getOption() {
			return option;
		}

	}

	public GPG() throws IOException {
		this.version = checkVersionInfo();
	}

	/**
	 * Create a tool which uses specified keyring files, as opposed to the gpg default ~/.gnupg based files.
	 * NB: this will fall back to default keyrings if either one of the parameters is null.
	 *
	 * @param publicKeyringFile
	 * @param secretKeyringFile
	 * @throws IOException
	 */
	public GPG(File publicKeyringFile, File secretKeyringFile) {
		try {
			this.version = checkVersionInfo();
			if (publicKeyringFile == null || secretKeyringFile == null) {
				throw new IllegalStateException("Must provide both public and private keyring file.");
			}
			// Open/create keyring files and check if they are valid GPG keyrings files
			runGPG("--no-default-keyring", "--keyring", publicKeyringFile.getAbsolutePath(), "--list-keys");
			this.publicKeyRingFile  = publicKeyringFile;
			runGPG("--no-default-keyring", "--secret-keyring", secretKeyringFile.getAbsolutePath(), "--list-secret-keys");
			this.secretKeyRingFile  = secretKeyringFile;
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Verify that gpg is installed and available on PATH.
	 *
	 * @return version string.
	 *
	 * @throws IOException
	 */
	private String checkVersionInfo() throws IOException {
		// TODO: maybe parse output for available Algorithms
		try (InputStream is = runGPG("--version").getStdOut();
				InputStreamReader isr = new InputStreamReader(is, Charsets.US_ASCII);
				BufferedReader reader = new BufferedReader(isr)) {
			return reader.readLine(); // auto-closes
		}
	}

	public void setTrustModel(TrustModel model) {
		this.trustModel = model;
	}

	private Process getProcess(List<String> command) throws IOException {
		GPGCommandBuilder builder = new GPGCommandBuilder();
		builder.withFlag("--batch")
			.withFlag("--yes")
			.withFlag("--no-tty");
		if (trustModel != null) {
			builder.withOption("--trust-model", trustModel.getOption());
		}
		if (publicKeyRingFile != null && secretKeyRingFile != null) {
			// Not operating on user's default keyring, supply proper parameters
			builder.withFlag("--no-default-keyring")
				.withOption("--secret-keyring", secretKeyRingFile.getAbsolutePath())
				.withOption("--keyring", publicKeyRingFile.getAbsolutePath());
		}
		builder.withOptions(command);
		ProcessBuilder pb = new ProcessBuilder(builder.build());
		log.debug("Starting: {}", StringUtils.join(builder.build(), ' '));
		return pb.start();
	}

	/**
	 * Run GPG
	 *
	 * @param command
	 * @return GPGOutStreams object holding cached streams of gpg's stdout and stderr output.
	 * @throws IOException
	 */
	private GPGOutStreams runGPG(String... command) throws IOException {
		Process process = getProcess(Arrays.asList(command));
		try {
			if (process.waitFor() != 0) {
				throw new GPGException(IOUtils.toString(process.getErrorStream()));
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		return new GPGOutStreams(process.getInputStream(), process.getErrorStream());
//		return IOUtils.toBufferedInputStream(process.getInputStream());
	}

	/**
	 * Run GPG and pipe data to process
	 *
	 * @param command
	 * @param data
	 * @return GPGOutStreams object holding cached streams of gpg's stdout and stderr output.
	 * @throws IOException
	 */
	private GPGOutStreams runGPG(List<String> command, byte[] data) throws IOException {
		Process process = getProcess(command);
		OutputStream processStdIn = process.getOutputStream();
		processStdIn.write(data);
		log.debug("piped {} bytes into child process stdin", data.length);
		processStdIn.flush();
		processStdIn.close();
		try {
			if (process.waitFor() != 0) {
				throw new GPGException(IOUtils.toString(process.getErrorStream()));
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		return new GPGOutStreams(process.getInputStream(), process.getErrorStream());
	}

	/**
	 * Run GPG and pipe data to process
	 *
	 * @param command
	 * @param data
	 * @return GPGOutStreams object holding cached streams of gpg's stdout and stderr output.
	 * @throws IOException
	 */
	private GPGOutStreams runGPG(List<String> command, InputStream data) throws IOException {
		Process process = getProcess(command);
		OutputStream processStdIn = process.getOutputStream();
		int bytes = IOUtils.copy(data, processStdIn);
		log.debug("piped {} bytes into child process stdin", bytes);
		processStdIn.flush();
		processStdIn.close();
		try {
			if (process.waitFor() != 0) {
				throw new GPGException(IOUtils.toString(process.getErrorStream()));
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		return new GPGOutStreams(process.getInputStream(), process.getErrorStream());
	}

	/**
	 * Get the version string (first line of gpg --version).
	 *
	 * @return
	 */
	public String getGPGVersion() {
		return this.version;
	}

	public List<GPGKeyInfo> getPublicKeyInfoList() throws IOException {
		ArrayList<GPGKeyInfo> res = new ArrayList<GPGKeyInfo>();
		String rawList = IOUtils.toString(runGPG("--fingerprint").getStdOut());
		return GPGKeyListParser.parse(rawList);
	}

	public List<GPGKeyInfo> getSecretKeyInfoList() throws IOException {
		ArrayList<GPGKeyInfo> res = new ArrayList<GPGKeyInfo>();
		String rawList = IOUtils.toString(runGPG("--list-secret-keys", "--with-fingerprint").getStdOut());
		return GPGKeyListParser.parse(rawList);
	}

	/**
	 * Import key from file to gpg keychain.
	 *
	 * @param file file containing pgp key
	 * @throws IOException
	 */
	public void importKey(File file) throws IOException {
		runGPG("--import", file.getAbsolutePath());
	}

	/**
	 * Import key bytes to gpg keychain.
	 *
	 * @param key key represented as bytes
	 * @throws IOException
	 */
	public void importKey(byte[] key) throws IOException {
		runGPG(Arrays.asList("--import"), key);
	}

	/**
	 * Import key bytes from stream to gpg keychain.
	 *
	 * @param key key represented as bytes
	 * @throws IOException
	 */
	public void importKey(InputStream key) throws IOException {
		runGPG(Arrays.asList("--import"), key);
	}

	/**
	 * Delete public key from gpg keychain by fingerprint
	 *
	 * @param hexFingerPrint hex encoded fingerprint of public key to delete
	 */
	public void deletePublicKey(String hexFingerPrint) throws IOException {
		if (!havePublicKey(hexFingerPrint)) {
			// Skip keys we don't have, gpg throws an error in these cases.
			return;
		}
		runGPG("--delete-key", "--batch", hexFingerPrint);
	}

	/**
	 * Delete secret key from gpg keychain by fingerprint
	 *
	 * @param hexFingerPrint hex encoded fingerprint of secret key to delete
	 * @throws IOException
	 */
	public void deleteSecretKey(String hexFingerPrint) throws IOException {
		if (!havePublicKey(hexFingerPrint)) {
			// Skip keys we don't have, gpg throws an error in these cases.
			return;
		}
		runGPG("--delete-secret-keys", "--batch", hexFingerPrint);
	}

	/**
	 * Check whether gpg store has specified key. We have to check this with exceptions since gpg gives
	 * return code 2 in the case we don't have the key.
	 *
	 * @param hexFingerPrint hex encoded key fingerprint.
	 * @return true if store contains key, false otherwise
	 * @throws IOException
	 */
	public boolean havePublicKey(String hexFingerPrint) throws IOException {
		try {
			runGPG("--fingerprint", hexFingerPrint);
			// No error means we have the key.
			return true;
		} catch (GPGException e) {
			if (!e.getMessage().contains("key not found")) {
				// Apparently we have an unexpected error (rather than the expected one)
				throw e;
			}
			return false;
		}
	}

	/**
	 * Check whether gpg store has specified key. We have to check this with exceptions since gpg gives
	 * return code 2 in the case we don't have the key.
	 *
	 * @param hexFingerPrint hex encoded key fingerprint.
	 * @return true if store contains key, false otherwise
	 * @throws IOException
	 */
	public boolean haveSecretKey(String hexFingerPrint) throws IOException {
		try {
			runGPG("--list-secret-keys", "--fingerprint", hexFingerPrint);
			// No error means we have the key.
			return true;
		} catch (GPGException e) {
			if (!e.getMessage().contains("key not found")) {
				// Apparently we have an unexpected error (rather than the expected one)
				throw e;
			}
			return false;
		}
	}

	/**
	 * Get the fingerprint for a keyring file.
	 *
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public String getFingerPrint(File file) throws IOException {
		String gpgOutput = IOUtils.toString(runGPG("--with-fingerprint", file.getAbsolutePath()).getStdOut());
		return parseGPGOutputForFingerPrint(gpgOutput);
	}

	/**
	 * Get the fingerprint for keyring bytes.
	 *
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public String getFingerPrint(byte[] key) throws IOException {
		String gpgOutput = IOUtils.toString(runGPG(Arrays.asList("--with-fingerprint"), key).getStdOut());
		return parseGPGOutputForFingerPrint(gpgOutput);
	}

	/**
	 * Get the fingerprint for keyring bytes.
	 *
	 * @param inputStream
	 * @return
	 * @throws IOException
	 */
	public String getFingerPrint(InputStream key) throws IOException {
		String gpgOutput = IOUtils.toString(runGPG(Arrays.asList("--with-fingerprint"), key).getStdOut());
		return parseGPGOutputForFingerPrint(gpgOutput);
	}

	/**
	 * @param gpgOutput
	 * @return fingerprint found in gpg output.
	 */
	private String parseGPGOutputForFingerPrint(String gpgOutput) {
		Matcher m = FINGERPRINT_PATTERN.matcher(gpgOutput);
		if(m.find()) {
			return m.group(1).replaceAll("\\s", "");
		}
		throw new IllegalStateException("Cannot find key fingerprint in unexpected output from GPG: " + gpgOutput);
	}

	/**
	 * Signs input with specified key and appends signature to input.
	 *
	 * @param input
	 * @param hexFingerPrint
	 * @param passphrase
	 * @return
	 * @throws IOException
	 */
	public InputStream sign(File input, String hexFingerPrint, String passphrase) throws IOException {
		//return runGPG("--passphrase", passphrase, "--sign", input.getAbsolutePath());
		return runGPG("--fingerprint",
				hexFingerPrint,
				"--passphrase",
				passphrase,
				"--output",
				"-",
				"--clearsign",
				input.getAbsolutePath()).getStdOut();
	}

	/**
	 * Signs input with specified key and appends signature to input.
	 *
	 * @param input
	 * @param hexFingerPrint
	 * @param passphrase
	 * @return
	 * @throws IOException
	 */
	public InputStream sign(byte[] input, String hexFingerPrint, String passphrase) throws IOException {
		//return runGPG("--passphrase", passphrase, "--sign", input.getAbsolutePath());
		return runGPG(Arrays.asList("--passphrase", passphrase, "--output", "-", "--clearsign"), input).getStdOut();
	}

	/**
	 * Signs input with specified key and appends signature to input.
	 *
	 * @param input
	 * @param hexFingerPrint
	 * @param passphrase
	 * @return
	 * @throws IOException
	 */
	public InputStream sign(InputStream input, String hexFingerPrint, String passphrase) throws IOException {
		//return runGPG("--passphrase", passphrase, "--sign", input.getAbsolutePath());
		return runGPG(Arrays.asList("--fingerprint",
				hexFingerPrint,
				"--passphrase",
				passphrase,
				"--output",
				"-",
				"--clearsign"), input).getStdOut();
	}

	/**
	 *
	 * Verify signed data.
	 *
	 * @param signed
	 * @return true if the data is correctly signed with a known key, false otherwise.
	 * @throws IOException
	 */
	public boolean verifySignature(InputStream signed) throws IOException {
		// For some reason gpg outputs the result of --verify on stderr instead of stdout
		String res = IOUtils.toString(runGPG(Arrays.asList("--verify"), signed).getStdErr());
		log.debug("Verify output {}", res);
		return res.contains("Good signature");
	}

	/**
	 *
	 * Verify signed data.
	 *
	 * @param signed
	 * @return true if the data is correctly signed with a known key, false otherwise.
	 * @throws IOException
	 */
	public boolean verifySignature(byte[] signed) throws IOException {
		// For some reason gpg outputs the result of --verify on stderr instead of stdout
		String res = IOUtils.toString(runGPG(Arrays.asList("--verify"), signed).getStdErr());
		return res.contains("Good signature");
	}

	/**
	 *
	 * Verify signed data.
	 *
	 * @param signed
	 * @return true if the data is correctly signed with a known key, false otherwise.
	 * @throws IOException
	 */
	public boolean verifySignature(File signed) throws IOException {
		// For some reason gpg outputs the result of --verify on stderr instead of stdout
		String res = IOUtils.toString(runGPG("--verify", signed.getAbsolutePath()).getStdErr());
		log.debug("Verify output {}", res);
		return res.contains("Good signature");
	}
	
		/**
	 *
	 * Verify signed data, with specific fingerprint
	 *
	 * @param signed
	 * @return true if the data is correctly signed with a specific known key, false otherwise.
	 * @throws IOException
	 */
	public boolean verifySignature(File signed, String hexFingerPrint) throws IOException {
		// For some reason gpg outputs the result of --verify on stderr instead of stdout
		String res = IOUtils.toString(runGPG("--verify", signed.getAbsolutePath()).getStdErr());
		log.debug("Verify output {}", res);
		res = res.replaceAll("\\s+","")
		return (res.contains("Goodsignature") && res.contains(fingerprint));
	}

	/**
	 * Encrypt contents of a file to stream.
	 *
	 * @param input the file to encrypt.
	 * @param hexFingerPrint fingerprint of encryption public key
	 * @return inputstream with ciphertext
	 * @throws IOException
	 */
	public InputStream encrypt(File input, String hexFingerPrint) throws IOException {
		return runGPG("-r", hexFingerPrint, "--encrypt", "--output", "-", input.getAbsolutePath()).getStdOut();
	}

	/**
	 * Encrypt contents of a file to file.
	 *
	 * @param input the file to encrypt.
	 * @param hexFingerPrint fingerprint of encryption public key
	 * @throws IOException
	 */
	public void encrypt(File input, File output, String hexFingerPrint) throws IOException {
		runGPG("-r", hexFingerPrint, "--encrypt", "--output", output.getAbsolutePath(), input.getAbsolutePath());
	}

	/**
	 * Encrypt a bytearray.
	 *
	 * @param bytes cleartext bytes.
	 * @param hexFingerPrint fingerprint of encryption public key
	 * @return InputStream providing ciphertext of bytes.
	 * @throws IOException
	 */
	public InputStream encrypt(byte[] bytes, String hexFingerPrint) throws IOException {
		return runGPG(Arrays.asList("-r", hexFingerPrint, "--encrypt", "--output", "-"), bytes).getStdOut();
	}

	/**
	 * Encrypt a bytearray to file.
	 *
	 * @param bytes cleartext bytes.
	 * @param output file to write ciphertext to
	 * @param hexFingerPrint fingerprint of encryption public key
	 * @throws IOException
	 */
	public void encrypt(byte[] bytes, File output, String hexFingerPrint) throws IOException {
		runGPG(Arrays.asList("-r", hexFingerPrint, "--encrypt", "--output", output.getAbsolutePath()), bytes);
	}

	/**
	 * Encrypt an inputstream to file.
	 *
	 * @param bytes cleartext bytes.
	 * @param output file to write ciphertext to
	 * @param hexFingerPrint fingerprint of encryption public key
	 * @throws IOException
	 */
	public void encrypt(InputStream clear, File output, String hexFingerPrint) throws IOException {
		runGPG(Arrays.asList("-r", hexFingerPrint, "--encrypt", "--output", output.getAbsolutePath()), clear);
	}

	/**
	 * Decrypt input file to stdout.
	 *
	 * @param input file with PGP encrypted data.
	 * @param passphrase passphrase for the secret key
	 * @return InputStream of cleartext
	 * @throws IOException
	 */
	public InputStream decrypt(File input, String passphrase) throws IOException {
		return runGPG("--passphrase", passphrase, "-d", input.getAbsolutePath()).getStdOut();
	}

	/**
	 * Decrypt input file to output file
	 *
	 * @param input file with PGP encrypted data.
	 * @param output file to write cleartext to.
	 * @param passphrase passphrase for the secret key
	 * @throws IOException
	 */
	public void decrypt(File input, File output, String passphrase) throws IOException {
		String outputPath = output.getAbsolutePath();
		String inputPath = input.getAbsolutePath();
		runGPG("--passphrase", passphrase,	"--output",	outputPath, inputPath);
	}

	/**
	 * Decrypt inputstream to stdout.
	 *
	 * @param cipherText
	 * @param passphrase
	 * @throws IOException
	 */
	public InputStream decrypt(InputStream cipherText, String passphrase) throws IOException {
		return runGPG(Arrays.asList("--passphrase", passphrase), cipherText).getStdOut();
	}

	public static class GPGException extends RuntimeException {

		public GPGException(String reason) {
			super(reason);
		}

	}

	private static final class GPGCommandBuilder {

		private final List<String> l = new ArrayList<>();

		GPGCommandBuilder() {
			l.add("gpg");
		}

		public void withOptions(List<String> command) {
			l.addAll(command);
		}

		public GPGCommandBuilder withOption(String option, String value) {
			l.add(option);
			l.add(value);
			return this;
		}

		public GPGCommandBuilder withFlag(String option) {
			l.add(option);
			return this;
		}

		public List<String> build() {
			return l;
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			for (String part : l) {
				sb.append(" ");
				sb.append(part);
			}
			return sb.toString();
		}

	}

	private static final class GPGOutStreams {

		private InputStream stdOut;
		private InputStream stdErr;

		public GPGOutStreams(InputStream gpgStdOut, InputStream gpgStdErr) {
			// We want to cache the stream contents for now, so we don't leak open streams from a Process instance.
			try {
				this.stdOut = IOUtils.toBufferedInputStream(gpgStdOut);
				this.stdErr = IOUtils.toBufferedInputStream(gpgStdErr);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		public InputStream getStdOut() {
			return stdOut;
		}

		public InputStream getStdErr() {
			return stdErr;
		}

	}

}
