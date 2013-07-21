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
 * Data container for 'SSH_FXP_ATTRS' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpAttrsReply extends BaseReply {

    private final FileAttributes attrs;

    /**
     * Creates a SshFxpAttrsReply instance.
     *
     * @param id    The reply id.
     * @param attrs The attributes.
     */
    public SshFxpAttrsReply(final int id, final FileAttributes attrs) {
        super(id);
        this.attrs = attrs;
    }

	/**
	 * {@inheritDoc}
	 */
	public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_ATTRS;
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
        return getName() + "[attrs=" + attrs + "]";
	}

	/**
	 * Returns the attributes.
	 * 
	 * @return the attributes.
	 */
	public FileAttributes getAttributes() {
		return attrs;
	}

}
