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

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.VendorIdParser.VendorId;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class VendorIdParser extends AbstractParser<VendorId> {
    /**
     * The &quot;vendor-id&quot; information as per
     * <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09 -
     * section 4.4</A>
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class VendorId {
        // CHECKSTYLE:OFF
        public String vendorName;
        public String productName;
        public String productVersion;
        public long productBuildNumber;
        // CHECKSTYLE:ON

        public VendorId() {
            super();
        }

        @Override
        public String toString() {
            return vendorName + "-" + productName + "-" + productVersion + "-" + productBuildNumber;
        }
    }

    public static final VendorIdParser INSTANCE = new VendorIdParser();

    public VendorIdParser() {
        super(SftpConstants.EXT_VENDOR_ID);
    }

    @Override
    public VendorId parse(byte[] input, int offset, int len) {
        return parse(new ByteArrayBuffer(input, offset, len));
    }

    public VendorId parse(Buffer buffer) {
        VendorId id = new VendorId();
        id.vendorName = buffer.getString();
        id.productName = buffer.getString();
        id.productVersion = buffer.getString();
        id.productBuildNumber = buffer.getLong();
        return id;
    }
}
