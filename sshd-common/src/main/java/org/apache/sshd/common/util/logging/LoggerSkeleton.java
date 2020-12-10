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

import org.slf4j.helpers.MarkerIgnoringBase;

/**
 * Provides some more default implementations for {@link org.slf4j.Logger} interface methods
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class LoggerSkeleton extends MarkerIgnoringBase {
    private static final long serialVersionUID = 1129569061632973648L;

    protected LoggerSkeleton(String name) {
        this.name = name;
    }

    @Override
    public void error(String format, Object arg) {
        if (isErrorEnabled()) {
            error(format, new Object[] { arg });
        }
    }

    @Override
    public void error(String format, Object arg1, Object arg2) {
        if (isErrorEnabled()) {
            error(format, new Object[] { arg1, arg2 });
        }
    }

    @Override
    public void error(String format, Object... arguments) {
        if (isErrorEnabled()) {
            error(LoggingUtils.formatMessage(format, arguments));
        }
    }

    @Override
    public void error(String msg) {
        error(msg, (Throwable) null);
    }

    @Override
    public void warn(String format, Object arg) {
        if (isWarnEnabled()) {
            warn(format, new Object[] { arg });
        }
    }

    @Override
    public void warn(String format, Object arg1, Object arg2) {
        if (isWarnEnabled()) {
            warn(format, new Object[] { arg1, arg2 });
        }
    }

    @Override
    public void warn(String format, Object... arguments) {
        if (isWarnEnabled()) {
            warn(LoggingUtils.formatMessage(format, arguments));
        }
    }

    @Override
    public void warn(String msg) {
        warn(msg, (Throwable) null);
    }

    @Override
    public void info(String format, Object arg) {
        if (isInfoEnabled()) {
            info(format, new Object[] { arg });
        }
    }

    @Override
    public void info(String format, Object arg1, Object arg2) {
        if (isInfoEnabled()) {
            info(format, new Object[] { arg1, arg2 });
        }
    }

    @Override
    public void info(String format, Object... arguments) {
        if (isInfoEnabled()) {
            info(LoggingUtils.formatMessage(format, arguments));
        }
    }

    @Override
    public void info(String msg) {
        if (isInfoEnabled()) {
            info(msg, (Throwable) null);
        }
    }

    @Override
    public void debug(String format, Object arg) {
        if (isDebugEnabled()) {
            debug(format, new Object[] { arg });
        }
    }

    @Override
    public void debug(String format, Object arg1, Object arg2) {
        if (isDebugEnabled()) {
            debug(format, new Object[] { arg1, arg2 });
        }
    }

    @Override
    public void debug(String format, Object... arguments) {
        if (isDebugEnabled()) {
            debug(LoggingUtils.formatMessage(format, arguments));
        }
    }

    @Override
    public void debug(String msg) {
        if (isDebugEnabled()) {
            debug(msg, (Throwable) null);
        }
    }

    @Override
    public void trace(String format, Object arg) {
        if (isTraceEnabled()) {
            trace(format, new Object[] { arg });
        }
    }

    @Override
    public void trace(String format, Object arg1, Object arg2) {
        if (isTraceEnabled()) {
            trace(format, new Object[] { arg1, arg2 });
        }
    }

    @Override
    public void trace(String format, Object... arguments) {
        if (isTraceEnabled()) {
            trace(LoggingUtils.formatMessage(format, arguments));
        }
    }

    @Override
    public void trace(String msg) {
        trace(msg, (Throwable) null);
    }
}
