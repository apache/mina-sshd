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

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.extensions.AclSupportedParser.AclCapabilities;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.LoggingUtils;

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

        private static class LazyAclCapabilityNameHolder {
            private static final String ACL_CAP_NAME_PREFIX = "SSH_ACL_CAP_";
            private static final Map<Integer, String> ACL_VALUES_MAP = LoggingUtils.generateMnemonicMap(SftpConstants.class, ACL_CAP_NAME_PREFIX);
            private static final Map<String, Integer> ACL_NAMES_MAP =
                    Collections.unmodifiableMap(GenericUtils.flipMap(ACL_VALUES_MAP, GenericUtils.<Integer>caseInsensitiveMap(), false));
        }

        @SuppressWarnings("synthetic-access")
        public static Map<String, Integer> getAclCapabilityNamesMap() {
            return LazyAclCapabilityNameHolder.ACL_NAMES_MAP;
        }

        /**
         * @param name The ACL capability name - may be without the &quot;SSH_ACL_CAP_xxx&quot; prefix.
         * Ignored if {@code null}/empty
         * @return The matching {@link Integer} value - or {@code null} if no match found
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
        public static Map<Integer, String> getAclCapabilityValuesMap() {
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

        public static Set<String> decodeAclCapabilities(int mask) {
            if (mask == 0) {
                return Collections.emptySet();
            }

            Set<String> caps = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            Map<Integer, String> map = getAclCapabilityValuesMap();
            for (Map.Entry<Integer, String> ae : map.entrySet()) {
                Integer value = ae.getKey();
                String name = ae.getValue();
                if ((mask & value.intValue()) != 0) {
                    caps.add(name);
                }
            }

            return caps;
        }

        public static int constructAclCapabilities(Collection<Integer> maskValues) {
            if (GenericUtils.isEmpty(maskValues)) {
                return 0;
            }

            int mask = 0;
            for (Integer v : maskValues) {
                mask |= v.intValue();
            }

            return mask;
        }

        public static Set<Integer> deconstructAclCapabilities(int mask) {
            if (mask == 0) {
                return Collections.emptySet();
            }

            Map<Integer, String> map = getAclCapabilityValuesMap();
            Set<Integer> caps = new HashSet<Integer>(map.size());
            for (Integer v : map.keySet()) {
                if ((mask & v.intValue()) != 0) {
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
