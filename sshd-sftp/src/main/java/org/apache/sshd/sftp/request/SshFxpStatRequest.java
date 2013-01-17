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
 * Data container for 'SSH_FXP_STAT' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpStatRequest extends BaseRequest {

	private final String path;
    private final int flags;

	/**
	 * Create a SshFxpStatRequest instance.
	 * 
	 * @param id   The request id.
	 * @param path The requested file path.
	 */
	public SshFxpStatRequest(final int id, final String path, final int flags) {
		super(id);
		this.path = path;
        this.flags = flags;
	}

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_STAT;
    }

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        return getName() + "[path=" + path + "]";
	}

	/**
	 * Returns the path.
	 * 
	 * @return The path.
	 */
	public String getPath() {
		return path;
	}

    public int getFlags() {
        return flags;
    }
}
