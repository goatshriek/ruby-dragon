package rubydragon.clojure;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

public class ClojureGhidraClassLoader extends ClassLoader {
	@Override
	public URL findResource(String path) {
		try {
			File file = new File(path);
			return file.toURI().toURL();
		} catch (MalformedURLException e) {
			return null;
		}
	}
}
