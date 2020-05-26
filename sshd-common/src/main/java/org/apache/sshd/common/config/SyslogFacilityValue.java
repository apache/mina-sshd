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

package org.apache.sshd.common.config;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5"><I>SyslogFacility</I> configuration
 *         value</A>
 */
public enum SyslogFacilityValue {
    DAEMON,
    USER,
    AUTH,
    LOCAL0,
    LOCAL1,
    LOCAL2,
    LOCAL3,
    LOCAL4,
    LOCAL5,
    LOCAL6,
    LOCAL7;

    public static final Set<SyslogFacilityValue> VALUES = Collections.unmodifiableSet(EnumSet.allOf(SyslogFacilityValue.class));

    public static SyslogFacilityValue fromName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (SyslogFacilityValue f : VALUES) {
            if (n.equalsIgnoreCase(f.name())) {
                return f;
            }
        }

        return null;
    }
}
