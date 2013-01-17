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
package org.apache.sshd.sftp.reply;

import java.util.Arrays;

/**
 * Data container for 'SSH_FXP_DATA' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpDataReply implements Reply {

	private final int id;
	private final Boolean lenFlag;
	private final byte[] data;

	/**
	 * Creates a SshFxpData instance.
	 * 
	 * @param id   The reply id.
	 * @param data The transfer data.
	 */
	public SshFxpDataReply(final int id, final byte[] data) {
		this.id   = id;
		this.data = Arrays.copyOfRange(data, 0, data.length);
		lenFlag  = null;
	}

	/**
	 * Creates a SshFxpData instance.
	 * 
	 * @param id      The reply id.
	 * @param data    The transfer data.
	 * @param lenFlag LenFlag.
	 */
	public SshFxpDataReply(final int id, final byte[] data, final boolean lenFlag) {
		this.id   = id;
		this.data = Arrays.copyOfRange(data, 0, data.length);
		this.lenFlag  = lenFlag;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getReplyCodeName() {
		return "SSH_FXP_DATA";
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		StringBuffer fs = new StringBuffer();
		fs.append(getReplyCodeName());
		fs.append(": id=");
		fs.append(id);
		fs.append(", data=<data(len=" + data.length + ")>");
		if (lenFlag != null) {
			fs.append(", len=");
			fs.append(lenFlag);
		}

		return fs.toString();
	}

	/**
	 * Returns the id.
	 * 
	 * @return The id.
	 */
	public long getId() {
		return id;
	}

	/**
	 * Returns the data.
	 * 
	 * @return The data.
	 */
	public byte[] getData() {
		return Arrays.copyOf(data, data.length);
	}

	/**
	 * Returns the lenflag.
	 * 
	 * @return The lenflag.
	 */
	public Boolean getLenFlag() {
		return lenFlag;
	}
}
