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

import org.apache.sshd.sftp.subsystem.SftpConstants;

/**
 * Data container for 'SSH_FXP_DATA' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpDataReply extends BaseReply {

	private final byte[] data;
    private final int offset;
    private final int length;
    private final boolean eof;

	/**
	 * Creates a SshFxpData instance.
	 * 
	 * @param id   The reply id.
	 * @param data The transfer data.
	 */
	public SshFxpDataReply(final int id, final byte[] data) {
        this(id, data, 0, data.length, false);
	}

	/**
	 * Creates a SshFxpData instance.
	 * 
	 * @param id      The reply id.
     * @param data    The transfer data.
     * @param offset  The offset in the data.
     * @param length  The length of data.
	 * @param eof     The EOF flag.
	 */
	public SshFxpDataReply(final int id, final byte[] data, final int offset, final int length, final boolean eof) {
        super(id);
		this.data = data;
        this.offset = offset;
        this.length = length;
		this.eof  = eof;
	}

	/**
	 * {@inheritDoc}
	 */
	public SftpConstants.Type getMessage() {
		return SftpConstants.Type.SSH_FXP_DATA;
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        return getName() + "[data=<data(len=" + length + ")>, eof=" + eof + "]";
	}

	/**
	 * Returns the data.
	 * 
	 * @return The data.
	 */
	public byte[] getData() {
		return data;
	}

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public boolean isEof() {
        return eof;
    }
}
