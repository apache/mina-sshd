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

import org.apache.sshd.sftp.Handle;

/**
 * Data container for 'SSH_FXP_HANDLE' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpHandleReply implements Reply {

	private final String handle;
	private final Handle handleRef;
	private final int id;

	/**
	 * Creates a SshFxpHandleReply instance.
	 * 
	 * @param id       The reply id.
	 * @param handle The handle name.
	 * @param handleRef   The handle.
	 */
	public SshFxpHandleReply(final int id, final String handle, final Handle handleRef) {
		this.id = id;
		this.handle = handle;
		this.handleRef = handleRef;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getReplyCodeName() {
		return "SSH_FXP_HANDLE";
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		return getReplyCodeName() + ": handle=" + handle + ", file=" + handleRef.getFile().getAbsolutePath();
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
	 * Returns the handle.
	 * 
	 * @return The handle.
	 */
	public String getHandle() {
		return handle;
	}
}
