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
package org.apache.sshd.sftp.subsystem;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.Session;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.Reply;
import org.apache.sshd.sftp.Request;
import org.apache.sshd.sftp.SftpSession;
import org.apache.sshd.sftp.Sftplet;
import org.apache.sshd.sftp.request.BaseRequest;


/**
 * The default Sftplet implementation.
 * It's just calling other added Sftplet implementations.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class DefaultSftpletContainer implements Sftplet {
	private List<Sftplet> sftpLetList = new ArrayList<Sftplet>();

    /**
     * {@inheritDoc}
     */
    public void onConnect(final SftpSession session) {
		for (Sftplet sftpLet : sftpLetList) {
			sftpLet.onConnect(session);
		}
	}

    /**
     * {@inheritDoc}
     */
	public void onDisconnect(final SftpSession session) {
		for (Sftplet sftpLet : sftpLetList) {
			sftpLet.onDisconnect(session);
		}
	}

    /**
     * {@inheritDoc}
     */
	public Reply beforeCommand(final SftpSession session, final Request sftpRequest) {
		Reply reply = null;
		for (Sftplet sftpLet : sftpLetList) {
			reply = sftpLet.beforeCommand(session, sftpRequest);
		}
		return reply;
	}

    /**
     * {@inheritDoc}
     */
	public Reply afterCommand(final SftpSession session, final Request sftpRequest, final Reply sftpReply)
			throws IOException {
		Reply reply = sftpReply;
		for (Sftplet sftpLet : sftpLetList) {
			reply = sftpLet.afterCommand(session, sftpRequest, reply);
		}
		return reply;
	}

    /**
     * {@inheritDoc}
     */
	public void add(final Sftplet sftpLet) {
		this.sftpLetList.add(sftpLet);
	}
}
