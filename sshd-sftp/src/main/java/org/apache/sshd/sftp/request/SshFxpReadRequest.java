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
 * Data container for 'SSH_FXP_READ' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpReadRequest extends BaseRequest {
	private final String handleId;
	private final long offset;
	private final Handle handle;
	private final int length;

	/**
	 * Creates a SshFxpReadRequest instance.
	 * 
	 * @param id       The request id.
	 * @param handleId The according file handle id.
	 * @param offset   The read offset.
	 * @param length   The length.
	 * @param handle   The according file handle.
	 */
	public SshFxpReadRequest(
			final int id, final String handleId, final long offset, final int length, final Handle handle) {
		super(id);
		this.handleId = handleId;
		this.offset = offset;
		this.length = length;
		this.handle = handle;
	}

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_READ;
    }

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        String ps;
        if (handle != null && handle.getFile() != null) {
            ps = handle.getFile().getAbsolutePath();
        } else {
            ps = "";
        }
        return getName() + "[handle=" + handleId + ", file=" + ps + ", offset=" + offset + ", length=" + length + "]";
	}

	/**
	 * Returns the according handle.
	 * 
	 * @return The according handle.
	 */
	public Handle getHandle() {
		return handle;
	}

	/**
	 * Returns the handle id.
	 * 
	 * @return The handle id.
	 */
	public String getHandleId() {
		return handleId;
	}

	/**
	 * Returns the length.
	 * 
	 * @return The length.
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns the offset.
	 * 
	 * @return The offset.
	 */
	public long getOffset() {
		return offset;
	}

}
