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

package org.apache.sshd.common.util.logging;

import java.util.logging.Level;

/**
 * Routes the effective logging to the {@link SimplifiedLog} methods.
 *
 * <B>Note:</B> we need the explicit overrides even though they are defined in {@link SimplifiedLog} as {@code default}
 * since they are defined as {@code abstract} in the {@code slf4j Logger} interface
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SimplifiedLoggerSkeleton extends LoggerSkeleton implements SimplifiedLog {
    public static final SimplifiedLoggerSkeleton EMPTY = new SimplifiedLoggerSkeleton("EMPTY") {
        private static final long serialVersionUID = 1L;

        @Override
        public boolean isEnabledLevel(Level level) {
            return false;
        }

        @Override
        public void log(Level level, Object message, Throwable t) {
            return;
        }

    };

    private static final long serialVersionUID = 9207771015837755402L;

    protected SimplifiedLoggerSkeleton(String name) {
        super(name);
    }

    @Override
    public boolean isErrorEnabled() {
        return SimplifiedLog.super.isErrorEnabled();
    }

    @Override
    public void error(String msg, Throwable err) {
        SimplifiedLog.super.error(msg, err);
    }

    @Override
    public boolean isWarnEnabled() {
        return SimplifiedLog.super.isWarnEnabled();
    }

    @Override
    public void warn(String msg, Throwable err) {
        SimplifiedLog.super.warn(msg, err);
    }

    @Override
    public boolean isInfoEnabled() {
        return SimplifiedLog.super.isInfoEnabled();
    }

    @Override
    public void info(String msg, Throwable err) {
        SimplifiedLog.super.info(msg, err);
    }

    @Override
    public boolean isDebugEnabled() {
        return SimplifiedLog.super.isDebugEnabled();
    }

    @Override
    public void debug(String msg, Throwable err) {
        SimplifiedLog.super.debug(msg, err);
    }

    @Override
    public boolean isTraceEnabled() {
        return SimplifiedLog.super.isTraceEnabled();
    }

    @Override
    public void trace(String msg, Throwable err) {
        SimplifiedLog.super.trace(msg, err);
    }
}
