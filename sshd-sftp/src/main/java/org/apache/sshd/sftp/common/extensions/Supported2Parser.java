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
import org.apache.sshd.sftp.common.extensions.Supported2Parser.Supported2;

/**
 * Parses the &quot;supported2&quot; extension as defined in
 * <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10">DRAFT 13 section 5.4</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Supported2Parser extends AbstractParser<Supported2> {
    /**
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     * @see    <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10">DRAFT 13 section 5.4</A>
     */
    public static class Supported2 {
        // CHECKSTYLE:OFF
        public int supportedAttributeMask;
        public int supportedAttributeBits;
        public int supportedOpenFlags;
        public int supportedAccessMask;
        public int maxReadSize;
        public short supportedOpenBlockVector;
        public short supportedBlock;
        //        uint32 attrib-extension-count
        public Collection<String> attribExtensionNames;
        //        uint32 extension-count
        public Collection<String> extensionNames;
        // CHECKSTYLE:ON

        public Supported2() {
            super();
        }

        @Override
        public String toString() {
            return "attrsMask=0x" + Integer.toHexString(supportedAttributeMask)
                   + ",attrsBits=0x" + Integer.toHexString(supportedAttributeBits)
                   + ",openFlags=0x" + Integer.toHexString(supportedOpenFlags)
                   + ",accessMask=0x" + Integer.toHexString(supportedAccessMask)
                   + ",maxRead=" + maxReadSize
                   + ",openBlock=0x" + Integer.toHexString(supportedOpenBlockVector & 0xFFFF)
                   + ",block=" + Integer.toHexString(supportedBlock & 0xFFFF)
                   + ",attribs=" + attribExtensionNames
                   + ",exts=" + extensionNames;
        }
    }

    public static final Supported2Parser INSTANCE = new Supported2Parser();

    public Supported2Parser() {
        super(SftpConstants.EXT_SUPPORTED2);
    }

    @Override
    public Supported2 parse(byte[] input, int offset, int len) {
        return parse(new ByteArrayBuffer(input, offset, len));
    }

    public Supported2 parse(Buffer buffer) {
        Supported2 sup2 = new Supported2();
        sup2.supportedAttributeMask = buffer.getInt();
        sup2.supportedAttributeBits = buffer.getInt();
        sup2.supportedOpenFlags = buffer.getInt();
        sup2.supportedAccessMask = buffer.getInt();
        sup2.maxReadSize = buffer.getInt();
        sup2.supportedOpenBlockVector = buffer.getShort();
        sup2.supportedBlock = buffer.getShort();
        sup2.attribExtensionNames = buffer.getStringList(true);
        sup2.extensionNames = buffer.getStringList(true);
        return sup2;
    }
}
