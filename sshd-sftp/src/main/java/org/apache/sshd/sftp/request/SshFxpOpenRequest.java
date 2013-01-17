/*
* Licensed to the Apache Software Foundation (ASF) under one
* or more contributor license agreements. See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership. The ASF licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.apache.sshd.sftp.request;

/**
 * Data container for 'SSH_FXP_OPEN' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpOpenRequest extends Request {
	private final int pflags;
	private final Integer acc;
	private final String path;

	/**
	 * Creates a SshFxpOpenRequest instance.
	 * 
	 * @param id     The request id.
	 * @param path   The path.
	 * @param pflags The flags.
	 */
	public SshFxpOpenRequest(final int id, String path, final int pflags) {
		super(id);
		this.path = path;
		this.pflags = pflags;
		this.acc = null;
	}

	/**
	 * Creates a SshFxpOpenRequest instance.
	 * 
	 * @param id     The request id.
	 * @param path   The path.
	 * @param acc    The acc.
	 * @param pflags The flags.
	 */
	public SshFxpOpenRequest(final int id, String path, final int acc, final int flags) {
		super(id);
		this.path = path;
		this.acc = acc;
		this.pflags = flags;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getName() {
		return "SSH_FXP_OPEN";
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        return "Status=" + getName();
	}

	/**
	 * Returns the path.
	 * 
	 * @return The path.
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Returns the flags.
	 * 
	 * @return The flags.
	 */
	public int getFlags() {
		return pflags;
	}

	/**
	 * Returns the acc.
	 * 
	 * @return The acc.
	 */
	public Integer getAcc() {
		return acc;
	}
}
