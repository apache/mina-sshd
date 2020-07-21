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

package org.apache.sshd.sftp.common.extensions;

import java.util.Collection;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.SupportedParser.Supported;

/**
 * Parses the &quot;supported&quot; extension as defined in
 * <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-05.txt">DRAFT 05 -
 * section 4.4</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SupportedParser extends AbstractParser<Supported> {
    /**
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-05.txt">DRAFT
     *         05 - section 4.4</A>
     */
    public static class Supported {
        // CHECKSTYLE:OFF
        public int supportedAttributeMask;
        public int supportedAttributeBits;
        public int supportedOpenFlags;
        public int supportedAccessMask;
        public int maxReadSize;
        public Collection<String> extensionNames;
        // CHECKSTYLE:ON

        public Supported() {
            super();
        }

        @Override
        public String toString() {
            return "attrsMask=0x" + Integer.toHexString(supportedAttributeMask)
                   + ",attrsBits=0x" + Integer.toHexString(supportedAttributeBits)
                   + ",openFlags=0x" + Integer.toHexString(supportedOpenFlags)
                   + ",accessMask=0x" + Integer.toHexString(supportedAccessMask)
                   + ",maxReadSize=" + maxReadSize
                   + ",extensions=" + extensionNames;
        }
    }

    public static final SupportedParser INSTANCE = new SupportedParser();

    public SupportedParser() {
        super(SftpConstants.EXT_SUPPORTED);
    }

    @Override
    public Supported parse(byte[] input, int offset, int len) {
        return parse(new ByteArrayBuffer(input, offset, len));
    }

    public Supported parse(Buffer buffer) {
        Supported sup = new Supported();
        sup.supportedAttributeMask = buffer.getInt();
        sup.supportedAttributeBits = buffer.getInt();
        sup.supportedOpenFlags = buffer.getInt();
        sup.supportedAccessMask = buffer.getInt();
        sup.maxReadSize = buffer.getInt();
        sup.extensionNames = buffer.getStringList(false);
        return sup;
    }
}
