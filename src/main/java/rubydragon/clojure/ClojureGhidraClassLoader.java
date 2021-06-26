package rubydragon.clojure;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

public class ClojureGhidraClassLoader extends ClassLoader {
	@Override
	public URL findResource(String path) {
		try {
			System.out.println("classloader called");
			File file = new File(path);
			return file.toURI().toURL();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
}
