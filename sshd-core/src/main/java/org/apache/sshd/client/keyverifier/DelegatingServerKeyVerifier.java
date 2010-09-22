/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.keyverifier;

import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Map;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.common.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * A ServerKeyVerifier that delegates verification to the ServerKeyVerifier found in the ClientSession metadata
 * The ServerKeyVerifier can be specified at the SshClient level, which may have connections to multiple hosts.
 * This technique lets each connection have its own ServerKeyVerifier.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DelegatingServerKeyVerifier implements ServerKeyVerifier {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
		Map<Object, Object> metadataMap = sshClientSession.getMetadataMap();
		Object verifier = metadataMap.get(ServerKeyVerifier.class);
		if (verifier == null) {
			log.trace("No verifier found in ClientSession metadata; accepting server key");
			return true;
		}
		// We throw if it's not a ServerKeyVerifier...
		return ((ServerKeyVerifier) verifier).verifyServerKey(sshClientSession, remoteAddress, serverKey);
	}
}
