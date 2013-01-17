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
package org.apache.sshd.sftp;

import org.apache.sshd.common.Session;

import java.io.IOException;



/**
 * Similar to org.apache.ftpserver.ftplet.Ftplet.
 * For custom command handling. For example adopting monoring tools, individual loggings, event processing,
 * customizing command processing.
 * There should be a ServerSession interface to avoid an implementation dependency.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface Sftplet {
	/**
	 * Client connect notification method.
	 * 
	 * @param session The according session.
	 */
	void onConnect(SftpSession session);

	/**
	 * Client disconnect notification method.
	 * 
	 * @param session The according session.
	 */
	void onDisconnect(SftpSession session);

	/**
	 * Called before the server invoke the command.
	 * 
	 * @param session     The according session.
	 * @param sftpRequest The sftp request.
	 * 
	 * @return If null, the standard processing goes on.
	 *         If not null, there will be no further processing and this reply will be returned to client.
	 */
	Reply beforeCommand(SftpSession session, Request sftpRequest);

	/**
	 * Called after the server as invoked the command.
	 * 
	 * @param session     The according session.
	 * @param sftpRequest The sftp request.
	 * @param sftpReply   The sftp reply.
	 * 
	 * @return If null, default sftp reply will be used.
	 *         If not null, there will be no further processing and this reply will be returned to client.
	 *         
	 * @throws IOException If an error occured. 
	 */
	Reply afterCommand(SftpSession session, Request sftpRequest, Reply sftpReply) throws IOException;
}
