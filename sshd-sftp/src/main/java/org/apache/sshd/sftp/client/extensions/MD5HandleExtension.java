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

package org.apache.sshd.sftp.client.extensions;

import java.io.IOException;

import org.apache.sshd.sftp.client.SftpClient;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
 *         - section 9.1.1</A>
 */
public interface MD5HandleExtension extends SftpClientExtension {
    /**
     * @param  handle      The (remote) file {@code Handle}
     * @param  offset      The offset to start calculating the hash
     * @param  length      The number of data bytes to calculate the hash on - if greater than available, then up to
     *                     whatever is available
     * @param  quickHash   A quick-hash of the 1st 2048 bytes - ignored if {@code null}/empty
     * @return             The hash value if the quick hash matches (or {@code null}/empty), or {@code null}/empty if
     *                     the quick hash is provided and it does not match
     * @throws IOException If failed to calculate the hash
     */
    byte[] getHash(SftpClient.Handle handle, long offset, long length, byte[] quickHash) throws IOException;

}
