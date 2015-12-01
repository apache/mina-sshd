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

package org.apache.sshd.common.subsystem.sftp.extensions;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.extensions.VersionsParser.Versions;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class VersionsParser extends AbstractParser<Versions> {
    /**
     * The &quot;versions&quot; extension data as per
     * <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09 Section 4.6</A>
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class Versions {
        public static final char SEP = ',';

        private List<String> versions;

        public Versions() {
            this(null);
        }

        public Versions(List<String> versions) {
            this.versions = versions;
        }

        public List<String> getVersions() {
            return versions;
        }

        public void setVersions(List<String> versions) {
            this.versions = versions;
        }

        @Override
        public String toString() {
            return GenericUtils.join(getVersions(), ',');
        }
    }

    public static final VersionsParser INSTANCE = new VersionsParser();

    public VersionsParser() {
        super(SftpConstants.EXT_VERSIONS);
    }

    @Override
    public Versions parse(byte[] input, int offset, int len) {
        return parse(new String(input, offset, len, StandardCharsets.UTF_8));
    }

    public Versions parse(String value) {
        String[] comps = GenericUtils.split(value, Versions.SEP);
        return new Versions(GenericUtils.isEmpty(comps) ? Collections.<String>emptyList() : Arrays.asList(comps));
    }
}
