// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021 Joel E. Anderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
