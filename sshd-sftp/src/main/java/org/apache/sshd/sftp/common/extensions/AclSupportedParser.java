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
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.AclSupportedParser.AclCapabilities;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AclSupportedParser extends AbstractParser<AclCapabilities> {
    /**
     * The &quot;acl-supported&quot; information as per
     * <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-11">DRAFT 11 - section 5.4</A>
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class AclCapabilities implements Serializable, Cloneable {
        private static final long serialVersionUID = -3118426327336468237L;
        private int capabilities;

        public AclCapabilities() {
            this(0);
        }

        public AclCapabilities(int capabilities) {
            // Protect against malicious or malformed packets
            ValidateUtils.checkTrue(
                    (capabilities >= 0) && (capabilities < SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT),
                    "Illogical ACL capabilities count: %d", capabilities);
            this.capabilities = capabilities;
        }

        public int getCapabilities() {
            return capabilities;
        }

        public void setCapabilities(int capabilities) {
            this.capabilities = capabilities;
        }

        @Override
        public int hashCode() {
            return getCapabilities();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (obj == this) {
                return true;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }

            return ((AclCapabilities) obj).getCapabilities() == getCapabilities();
        }

        @Override
        public AclCapabilities clone() {
            try {
                return getClass().cast(super.clone());
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException("Failed to clone " + toString() + ": " + e.getMessage(), e);
            }
        }

        @Override
        public String toString() {
            return Objects.toString(decodeAclCapabilities(getCapabilities()));
        }

        private static final class LazyAclCapabilityNameHolder {
            private static final String ACL_CAP_NAME_PREFIX = "SSH_ACL_CAP_";
            private static final NavigableMap<Integer, String> ACL_VALUES_MAP
                    = LoggingUtils.generateMnemonicMap(SftpConstants.class, ACL_CAP_NAME_PREFIX);
            private static final NavigableMap<String, Integer> ACL_NAMES_MAP = Collections.unmodifiableNavigableMap(
                    GenericUtils.flipMap(
                            ACL_VALUES_MAP, GenericUtils.caseInsensitiveMap(), false));

            private LazyAclCapabilityNameHolder() {
                throw new UnsupportedOperationException("No instance allowed");
            }
        }

        @SuppressWarnings("synthetic-access")
        public static NavigableMap<String, Integer> getAclCapabilityNamesMap() {
            return LazyAclCapabilityNameHolder.ACL_NAMES_MAP;
        }

        /**
         * @param  name The ACL capability name - may be without the &quot;SSH_ACL_CAP_xxx&quot; prefix. Ignored if
         *              {@code null}/empty
         * @return      The matching {@link Integer} value - or {@code null} if no match found
         */
        public static Integer getAclCapabilityValue(String name) {
            if (GenericUtils.isEmpty(name)) {
                return null;
            }

            name = name.toUpperCase();
            if (!name.startsWith(LazyAclCapabilityNameHolder.ACL_CAP_NAME_PREFIX)) {
                name += LazyAclCapabilityNameHolder.ACL_CAP_NAME_PREFIX;
            }

            Map<String, Integer> map = getAclCapabilityNamesMap();
            return map.get(name);
        }

        @SuppressWarnings("synthetic-access")
        public static NavigableMap<Integer, String> getAclCapabilityValuesMap() {
            return LazyAclCapabilityNameHolder.ACL_VALUES_MAP;
        }

        public static String getAclCapabilityName(int aclCapValue) {
            Map<Integer, String> map = getAclCapabilityValuesMap();
            String name = map.get(aclCapValue);
            if (GenericUtils.isEmpty(name)) {
                return Integer.toString(aclCapValue);
            } else {
                return name;
            }
        }

        public static NavigableSet<String> decodeAclCapabilities(int mask) {
            if (mask == 0) {
                return Collections.emptyNavigableSet();
            }

            NavigableSet<String> caps = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            Map<Integer, String> map = getAclCapabilityValuesMap();
            map.forEach((value, name) -> {
                if ((mask & value) != 0) {
                    caps.add(name);
                }
            });

            return caps;
        }

        public static int constructAclCapabilities(Collection<Integer> maskValues) {
            if (GenericUtils.isEmpty(maskValues)) {
                return 0;
            }

            int mask = 0;
            for (Integer v : maskValues) {
                mask |= v;
            }

            return mask;
        }

        public static Set<Integer> deconstructAclCapabilities(int mask) {
            if (mask == 0) {
                return Collections.emptySet();
            }

            Map<Integer, String> map = getAclCapabilityValuesMap();
            Set<Integer> caps = new HashSet<>(map.size());
            for (Integer v : map.keySet()) {
                if ((mask & v) != 0) {
                    caps.add(v);
                }
            }

            return caps;
        }
    }

    public static final AclSupportedParser INSTANCE = new AclSupportedParser();

    public AclSupportedParser() {
        super(SftpConstants.EXT_ACL_SUPPORTED);
    }

    @Override
    public AclCapabilities parse(byte[] input, int offset, int len) {
        return parse(new ByteArrayBuffer(input, offset, len));
    }

    public AclCapabilities parse(Buffer buffer) {
        return new AclCapabilities(buffer.getInt());
    }
}
