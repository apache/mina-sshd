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

import org.apache.sshd.server.SshFile;

/**
 * Data container for 'SSH_FXP_ATTRS' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpAttrsReply implements Reply {

	private int id;
	private final SshFile file;
	private final Integer flags;

	/**
	 * Creates a SshFxpAttrsReply instance.
	 * 
	 * @param id    The reply id.
	 * @param file  The according file.
	 * @param flags The file flags.
	 */
	public SshFxpAttrsReply(final int id, final SshFile file, final int flags) {
		this.id = id;
		this.file = file;
		this.flags = flags;
	}

	/**
	 * Creates a SshFxpAttrsReply instance.
	 * 
	 * @param id    The reply id.
	 * @param file  The according file.
	 */
	public SshFxpAttrsReply(final int id, final SshFile file) {
		this.id = id;
		this.file = file;
		this.flags = null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getReplyCodeName() {
		return "SSH_FXP_ATTRS";
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(getReplyCodeName());
		sb.append(": id=");
		sb.append(id);
		sb.append(", file=");
		sb.append(file.getAbsolutePath());
		sb.append(", flags=");
		sb.append(flags);

		return sb.toString();
	}

	/**
	 * Returns the id.
	 * 
	 * @return The id.
	 */
	public int getId() {
		return id;
	}

	/**
	 * Returns the file.
	 * 
	 * @return the file.
	 */
	public SshFile getFile() {
		return file;
	}

	/**
	 * Returns the flags.
	 * 
	 * @return The flags.
	 */
	public Integer getFlags() {
		return flags;
	}
}
