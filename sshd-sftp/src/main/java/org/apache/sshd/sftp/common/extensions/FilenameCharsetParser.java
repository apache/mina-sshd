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

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.FilenameCharsetParser.FilenameCharset;

/**
 * Parses the &quot;filename-charset&quot; extension
 *
 * @see    <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-16">DRAFT 13 - page-16</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FilenameCharsetParser extends AbstractParser<FilenameCharset> {
    /**
     * Encapsulates the &quot;filename-charset&quot; extension information
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class FilenameCharset implements Serializable, Cloneable {
        private static final long serialVersionUID = -4848766176935392024L;

        private String charset;

        public FilenameCharset() {
            this(null);
        }

        public FilenameCharset(String charset) {
            this.charset = charset;
        }

        public String getCharset() {
            return charset;
        }

        public void setCharset(String charset) {
            this.charset = charset;
        }

        @Override
        public FilenameCharset clone() {
            try {
                return getClass().cast(super.clone());
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException("Failed to clone " + toString() + ": " + e.getMessage(), e);
            }
        }

        @Override
        public int hashCode() {
            return GenericUtils.hashCode(getCharset(), Boolean.TRUE);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if ((o == null) || (o.getClass() != getClass())) {
                return false;
            }

            return GenericUtils.safeCompare(this.getCharset(), ((FilenameCharset) o).getCharset(), false) == 0;
        }

        @Override
        public String toString() {
            return getCharset();
        }
    }

    public static final FilenameCharsetParser INSTANCE = new FilenameCharsetParser();

    public FilenameCharsetParser() {
        super(SftpConstants.EXT_FILENAME_CHARSET);
    }

    @Override
    public FilenameCharset parse(byte[] input, int offset, int len) {
        return parse(new String(input, offset, len, StandardCharsets.UTF_8));
    }

    public FilenameCharset parse(String s) {
        return new FilenameCharset(s);
    }
}
