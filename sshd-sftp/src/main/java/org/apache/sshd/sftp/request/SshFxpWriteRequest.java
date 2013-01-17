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

import java.util.Arrays;

import org.apache.sshd.sftp.Handle;
import org.apache.sshd.sftp.subsystem.SftpConstants;

/**
 * Data container for 'SSH_FXP_WRITE' request.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpWriteRequest extends BaseRequest {
	private final String handleId;
	private final long offset;
	private final Handle handle;
	private final byte[] data;

	/**
	 * Creates a SshFxpWriteRequest instance.
	 * 
	 * @param id       The request id.
	 * @param handleId The according file handle id.
	 * @param offset   The write offset.
	 * @param data     The write data.
	 * @param handle   The according file handle.
	 */
	public SshFxpWriteRequest(
			final int id, final String handleId, final long offset, final byte[] data, final Handle handle) {
		super(id);
		this.handleId = handleId;
		this.offset   = offset;
		this.data     = Arrays.copyOf(data, data.length);
		this.handle   = handle;
	}

	/**
	 * Returns the write data.
	 * 
	 * @return The write data.
	 */
	public byte[] getData() {
		return Arrays.copyOf(data, data.length);
	}

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_WRITE;
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
        return getName() + "[handle=" + handleId + ", file=" + ps + ", offset=" + offset + ", length=" + data.length + "]";
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
	 * Returns the offset.
	 * 
	 * @return The offset.
	 */
	public long getOffset() {
		return offset;
	}
}
