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
import java.util.Collection;
import java.util.Map;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
 *         - section 9.1.2</A>
 */
public interface CheckFileNameExtension extends SftpClientExtension {
    /**
     * @param  name        Remote file name/path
     * @param  algorithms  Hash algorithms in preferred order
     * @param  startOffset Start offset of the hash
     * @param  length      Length of data to hash - if zero then till EOF
     * @param  blockSize   Input block size to calculate individual hashes - if zero the <U>one</U> hash of <U>all</U>
     *                     the data
     * @return             An <U>immutable</U> {@link java.util.Map.Entry} key left=hash algorithm name, value=the
     *                     calculated hashes.
     * @throws IOException If failed to execute the command
     */
    Map.Entry<String, Collection<byte[]>> checkFileName(
            String name, Collection<String> algorithms, long startOffset, long length, int blockSize)
            throws IOException;
}
