package rubydragon.clojure;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Custom classloader for Clojure scripts so that they don't have to be in the
 * classpath in order to be run.
 */
public class ClojureGhidraClassLoader extends ClassLoader {

	/**
	 * If the provided resource ends with ".clj", then the loader attempts to find
	 * it as a raw file, without using the classpath.
	 *
	 * If the resource doesn't end with ".clj", then this classloader simply defers
	 * to its parent.
	 *
	 * @param path The path to the resource. If this is a clojure script, it is
	 *             expected to be a findable path.
	 */
	@Override
	public URL findResource(String path) {
		if (!path.endsWith(".clj")) {
			return super.findResource(path);
		}

		try {
			File file = new File(path);
			return file.toURI().toURL();
		} catch (MalformedURLException e) {
			return null;
		}
	}
}
