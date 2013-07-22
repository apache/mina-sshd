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

import java.io.IOException;

import org.apache.sshd.sftp.subsystem.SftpConstants;

import static org.apache.sshd.sftp.subsystem.SftpConstants.*;

/**
 * Data container for 'SSH_FXP_STATUS' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpStatusReply extends BaseReply {

	private String substatusAsSTR;
	private String msg;
	private String lang;
	private final int substatus;

    /**
     * Creates a SshFxpStatusReply instance.
     *
     * @param id        The reply id.
     * @param substatus The sub status.
     * @param msg       The status message.
     *
     * @throws IOException If the given reply is unsupported.
     */
    public SshFxpStatusReply(final int id, final int substatus, final String msg)
            throws IOException {
        this(id, substatus, msg, "");
    }

	/**
	 * Creates a SshFxpStatusReply instance.
	 * 
	 * @param id        The reply id.
	 * @param substatus The sub status.
	 * @param msg       The status message.
	 * @param lang      The lang status message.
	 * 
	 * @throws IOException If the given reply is unsupported. 
	 */
	public SshFxpStatusReply(final int id, final int substatus, final String msg, final String lang)
			throws IOException {
        super(id);
		this.substatus = substatus;
		this.lang = lang;
		this.msg = msg;

    	switch (substatus) {
		case SSH_FX_FILE_ALREADY_EXISTS:
			substatusAsSTR = "SSH_FX_FILE_ALREADY_EXISTS";
			break;
		case SSH_FX_DIR_NOT_EMPTY:
			substatusAsSTR = "SSH_FX_DIR_NOT_EMPTY";
			break;
		case SSH_FX_EOF:
			substatusAsSTR = "SSH_FX_EOF";
			break;
		case SSH_FX_FILE_IS_A_DIRECTORY:
			substatusAsSTR = "SSH_FX_FILE_IS_A_DIRECTORY";
			break;
		case SSH_FX_INVALID_HANDLE:
			substatusAsSTR = "SSH_FX_INVALID_HANDLE";
			break;
		case SSH_FX_NO_SUCH_FILE:
			substatusAsSTR = "SSH_FX_NO_SUCH_FILE";
			break;
		case SSH_FX_NO_SUCH_PATH:
			substatusAsSTR = "SSH_FX_NO_SUCH_PATH";
			break;
		case SSH_FX_NOT_A_DIRECTORY:
			substatusAsSTR = "SSH_FX_NOT_A_DIRECTORY";
			break;
		case SSH_FX_OK:
			substatusAsSTR = "SSH_FX_OK";
			break;
		case SSH_FX_OP_UNSUPPORTED:
			substatusAsSTR = "SSH_FX_OP_UNSUPPORTED";
			break;
		case SSH_FX_FAILURE:
			substatusAsSTR = "SSH_FX_FAILURE";
			break;
		case SSH_FX_PERMISSION_DENIED:
			substatusAsSTR = "SSH_FX_PERMISSION_DENIED";
			break;
		case SSH_FXP_MKDIR:
			substatusAsSTR = "SSH_FXP_MKDIR";
			break;
		case SSH_FXP_REMOVE:
			substatusAsSTR = "SSH_FXP_REMOVE";
			break;
		case SSH_FXP_RMDIR:
			substatusAsSTR = "SSH_FXP_RMDIR";
			break;
		case SSH_FX_WRITE_PROTECT:
			substatusAsSTR = "SSH_FX_WRITE_PROTECT";
			break;
		default:
			throw new IOException("Internal error - unexpected substatus: " + substatus);
		}
	}

	/**
	 * Returns the substatus.
	 * 
	 * @return The substatus.
	 */
	public int getSubstatus() {
		return substatus;
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		return getName() + "[status=" + substatusAsSTR + ", msg=" + msg + "]";
	}

	/**
	 * {@inheritDoc}
	 */
	public SftpConstants.Type getMessage() {
		return SftpConstants.Type.SSH_FXP_STATUS;
	}

	/**
	 * Returns the status message.
	 * 
	 * @return The status message.
	 */
	public String getMsg() {
		return msg;
	}

	/**
	 * Returns the long status message.
	 * 
	 * @return The long status message.
	 */
	public String getLang() {
		return lang;
	}
}
