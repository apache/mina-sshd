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

package org.apache.sshd.cli;

import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CliLogger {
    public static final DateFormat LOG_TIME_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");

    protected final Level threshold;
    protected final PrintStream logStream;

    public CliLogger(Level threshold, PrintStream logStream) {
        this.threshold = threshold;
        this.logStream = logStream;
    }

    public boolean isErrorEnabled() {
        return isEnabledLevel(Level.SEVERE);
    }

    public void error(String msg) {
        error(msg, null);
    }

    public void error(String msg, Throwable err) {
        log(Level.SEVERE, msg, err);
    }

    public boolean isWarnEnabled() {
        return isEnabledLevel(Level.WARNING);
    }

    public void warn(String msg) {
        warn(msg, null);
    }

    public void warn(String msg, Throwable err) {
        log(Level.WARNING, msg, err);
    }

    public boolean isInfoEnabled() {
        return isEnabledLevel(Level.INFO);
    }

    public void info(String msg) {
        info(msg, null);
    }

    public void info(String msg, Throwable err) {
        log(Level.INFO, msg, err);
    }

    public boolean isDebugEnabled() {
        return isEnabledLevel(Level.FINE);
    }

    public void debug(String msg) {
        debug(msg, null);
    }

    public void debug(String msg, Throwable err) {
        log(Level.FINE, msg, err);
    }

    public boolean isTraceEnabled() {
        return isEnabledLevel(Level.FINER);
    }

    public void trace(String msg) {
        trace(msg, null);
    }

    public void trace(String msg, Throwable err) {
        log(Level.FINER, msg, err);
    }

    public boolean isEnabledLevel(Level level) {
        return isLevelEnabled(level, threshold);
    }

    public void log(Level level, String msg, Throwable err) {
        if (!isEnabledLevel(level)) {
            return;
        }

        Date now = new Date();
        String time;
        synchronized (LOG_TIME_FORMATTER) {
            time = LOG_TIME_FORMATTER.format(now);
        }
        logStream.append(time)
                .append(' ').append(level.getName())
                .append(' ').append(Thread.currentThread().getName())
                .append(' ').append(msg)
                .println();
        if (err != null) {
            err.printStackTrace(logStream);
        }
    }

    public static boolean isErrorEnabled(Level level) {
        return isLevelEnabled(level, Level.SEVERE);
    }

    public static boolean isWarnEnabled(Level level) {
        return isLevelEnabled(level, Level.WARNING);
    }

    public static boolean isInfoEnabled(Level level) {
        return isLevelEnabled(level, Level.INFO);
    }

    public static boolean isDebugEnabled(Level level) {
        return isLevelEnabled(level, Level.FINE);
    }

    public static boolean isTraceEnabled(Level level) {
        return isLevelEnabled(level, Level.FINER);
    }

    public static boolean isLevelEnabled(Level level, Level threshold) {
        return (level != null) && (threshold != null) && (level.intValue() <= threshold.intValue());
    }
}
