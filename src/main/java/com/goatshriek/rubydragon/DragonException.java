// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021-2025 Joel E. Anderson
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

package com.goatshriek.rubydragon;

/**
 * A generic exception from RubyDragon.
 *
 * This class shouldn't be used directly, instead it should be extended and then
 * the more specific child should be thrown instead.
 */
public class DragonException extends Exception {
	/**
	 * Auto-generated serial version UID.
	 */
	private static final long serialVersionUID = -7049257880213278474L;

	/**
	 * A new generic RubyDragon exception.
	 *
	 * @param message A description of the issue encountered.
	 */
	public DragonException(String message) {
		super(message);
	}
}
