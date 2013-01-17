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

import org.apache.sshd.sftp.subsystem.SftpConstants;

/**
 * Data container for 'SSH_FXP_RENAME' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpRenameRequest extends BaseRequest {
	private final String oldPath;
	private final String newPath;

	/**
	 * Create a SshFxpRenameRequest instance.
	 * 
	 * @param id      The request id.
	 * @param oldPath The old path.
	 * @param newPath The new path.
	 */
	public SshFxpRenameRequest(final int id, final String oldPath, final String newPath) {
		super(id);
		this.oldPath = oldPath;
		this.newPath = newPath;
	}

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_RENAME;
    }

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        return getName() + "[old=" + oldPath + ", new=" + newPath + "]";
	}

	/**
	 * Returns the old path.
	 * 
	 * @return The old path.
	 */
	public String getOldPath() {
		return oldPath;
	}

	/**
	 * Returns the new path.
	 * 
	 * @return The new path.
	 */
	public String getNewPath() {
		return newPath;
	}
}
