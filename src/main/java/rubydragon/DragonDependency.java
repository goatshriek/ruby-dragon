package rubydragon;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.kotlin.konan.file.File;

/**
 * Describes a dependency that a RubyDragon plugin needs to function properly.
 * These are most often jars that provide runtime environments for supported
 * languages.
 *
 * @param url    The URL that the dependency should be downloaded from.
 *
 * @param sha256 A hex representation of the expected SHA 256 sum of the
 *               dependency file. This will be used to validate the file after
 *               downloading it.
 */
public class DragonDependency {
	private URL url;
	private byte[] sha256;

	public DragonDependency(URL url, String sha256) {
		this.url = url;

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
	public void download(String path) throws IOException, NoSuchAlgorithmException {
		int downloadChunkSize = 4096;

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		InputStream downloadStream = new DigestInputStream(url.openStream(), md);
		OutputStream fileStream = new FileOutputStream(path);
		OutputStream saveStream = new BufferedOutputStream(fileStream, downloadChunkSize);

		byte[] chunk = new byte[downloadChunkSize];
		int bytesDownloaded;
		do {
			bytesDownloaded = downloadStream.read(chunk);
			saveStream.write(chunk);
		} while (bytesDownloaded != 0);

		downloadStream.close();
		saveStream.close();

		byte[] actualSha256 = md.digest();
		if (!MessageDigest.isEqual(sha256, actualSha256)) {
			File outFile = new File(path);
			outFile.delete();
			throw new RuntimeException("SHA 256 sum did not match the expected value");
		}
	}
}
