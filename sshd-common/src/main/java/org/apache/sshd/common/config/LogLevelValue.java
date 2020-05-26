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
import java.util.logging.Level;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html"><I>LogLevel</I>
 *         configuration value</A>
 */
public enum LogLevelValue {
    /*
     * NOTE(s): 1. DEBUG and DEBUG1 are EQUIVALENT 2. Order is important (!!!)
     */
    QUIET(Level.OFF),
    FATAL(Level.SEVERE),
    ERROR(Level.SEVERE),
    INFO(Level.INFO),
    VERBOSE(Level.FINE),
    DEBUG(Level.FINE),
    DEBUG1(Level.FINE),
    DEBUG2(Level.FINER),
    DEBUG3(Level.FINEST);

    public static final Set<LogLevelValue> VALUES = Collections.unmodifiableSet(EnumSet.allOf(LogLevelValue.class));

    private final Level level;

    LogLevelValue(Level level) {
        this.level = level;
    }

    public Level getLoggingLevel() {
        return level;
    }

    public static LogLevelValue fromName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (LogLevelValue l : VALUES) {
            if (n.equalsIgnoreCase(l.name())) {
                return l;
            }
        }

        return null;
    }
}
