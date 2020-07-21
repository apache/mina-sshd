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

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.NewlineParser.Newline;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NewlineParser extends AbstractParser<Newline> {
    /**
     * The &quot;newline&quot; extension information as per
     * <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
     * Section 4.3</A>
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class Newline implements Cloneable, Serializable {
        private static final long serialVersionUID = 2010656704254497899L;
        private String newline;

        public Newline() {
            this(null);
        }

        public Newline(String newline) {
            this.newline = newline;
        }

        public String getNewline() {
            return newline;
        }

        public void setNewline(String newline) {
            this.newline = newline;
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(getNewline());
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (obj == this) {
                return true;
            }
            if (obj.getClass() != getClass()) {
                return false;
            }

            return Objects.equals(((Newline) obj).getNewline(), getNewline());
        }

        @Override
        public Newline clone() {
            try {
                return getClass().cast(super.clone());
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException("Failed to clone " + toString() + ": " + e.getMessage(), e);
            }
        }

        @Override
        public String toString() {
            String nl = getNewline();
            if (GenericUtils.isEmpty(nl)) {
                return nl;
            } else {
                return BufferUtils.toHex(':', nl.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    public static final NewlineParser INSTANCE = new NewlineParser();

    public NewlineParser() {
        super(SftpConstants.EXT_NEWLINE);
    }

    @Override
    public Newline parse(byte[] input, int offset, int len) {
        return parse(new String(input, offset, len, StandardCharsets.UTF_8));
    }

    public Newline parse(String value) {
        return new Newline(value);
    }
}
