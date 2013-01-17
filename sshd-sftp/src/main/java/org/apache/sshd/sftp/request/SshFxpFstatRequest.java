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

import org.apache.sshd.sftp.Handle;
import org.apache.sshd.sftp.subsystem.SftpConstants;

/**
 * Data container for 'SSH_FXP_FSTAT' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpFstatRequest extends BaseRequest {
	private final String handle;
	private final Handle handleRef;

	/**
	 * Creates a SshFxpFstatRequest instance.
	 * 
	 * @param id        The request id.
	 * @param handle    The handle.
	 * @param handleRef The handle reference.
	 */
	public SshFxpFstatRequest(final int id, final String handle, final Handle handleRef) {
		super(id);
		this.handle = handle;
		this.handleRef = handleRef;
	}

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_FSTAT;
    }

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		String ps;
		if (handleRef != null && handleRef.getFile() != null) {
			ps = handleRef.getFile().getAbsolutePath();
		} else {
			ps = "";
		}
        return getName() + "[handle=" + handle + ", file=" + ps + "]";
	}

	/**
	 * Returns the handle id.
	 * 
	 * @return The handle id.
	 */
	public String getHandleId() {
		return handle;
	}
}
