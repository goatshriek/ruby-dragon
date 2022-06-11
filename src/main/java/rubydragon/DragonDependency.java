package rubydragon;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

// this non-standard import is necessary until Java 17, when
// java.util.HexFormat is available
import org.bouncycastle.util.encoders.Hex;

/**
 * Describes a dependency that a RubyDragon plugin needs to function properly.
 * These are most often jars that provide runtime environments for supported
 * languages.
 *
 * @param url         The URL that the dependency should be downloaded from.
 *
 * @param sha256Bytes A hex representation of the expected SHA 256 sum of the
 *                    dependency file. This will be used to validate the file
 *                    after downloading it.
 */
public class DragonDependency {
	private String name;
	private URL url;
	private byte[] sha256;

	public DragonDependency(String name, String url, String sha256) {
		this.name = name;

		try {
			this.url = new URL(url);
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		ByteArrayOutputStream shaBytes = new ByteArrayOutputStream(256);
		try {
			Hex.decode(sha256, shaBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.sha256 = shaBytes.toByteArray();
	}

	/**
	 * Downloads this dependency to the provided location.
	 *
	 * @param path The path to place the file at once it is downloaded.
	 *
	 * @throws IOException              If the input stream can't be opened.
	 * @throws NoSuchAlgorithmException If the platform does not support SHA-256
	 *                                  digests.
	 */
	public void download(Path path) throws IOException, NoSuchAlgorithmException {
		int downloadChunkSize = 4096;

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		InputStream downloadStream = new DigestInputStream(url.openStream(), md);
		File downloadFile = path.resolve(name).toFile();
		OutputStream fileStream = new FileOutputStream(downloadFile);
		OutputStream saveStream = new BufferedOutputStream(fileStream, downloadChunkSize);

		byte[] chunk = new byte[downloadChunkSize];
		int bytesDownloaded = downloadStream.read(chunk);
		while (bytesDownloaded != -1) {
			saveStream.write(chunk, 0, bytesDownloaded);
			bytesDownloaded = downloadStream.read(chunk);
		}

		downloadStream.close();
		saveStream.close();

		byte[] actualSha256 = md.digest();
		if (!MessageDigest.isEqual(sha256, actualSha256)) {
			downloadFile.delete();
			throw new RuntimeException("SHA 256 sum did not match the expected value for " + name + ", expected: `"
					+ Hex.toHexString(sha256) + ", actual: `" + Hex.toHexString(actualSha256) + "'");
		}
	}

	/**
	 * Gets the name of this dependency.
	 */
	public String getName() {
		return name;
	}

	/**
	 * String representation of the dependency name, url, and sha256 sum.
	 */
	@Override
	public String toString() {
		return name + ": " + url.toString() + " (" + Hex.toHexString(sha256) + ")";
	}
}
