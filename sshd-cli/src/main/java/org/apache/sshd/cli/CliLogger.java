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
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Level;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.LogLevelValue;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NullPrintStream;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.apache.sshd.common.util.logging.SimplifiedLoggerSkeleton;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CliLogger extends SimplifiedLoggerSkeleton {
    public static final DateFormat LOG_TIME_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");

    private static final long serialVersionUID = -3785762030194772776L;
    private static final NullPrintStream NULL_PRINT_STREAM = new NullPrintStream();

    protected final Level threshold;
    protected final PrintStream logStream;

    protected CliLogger(String name, Level threshold, PrintStream logStream) {
        super(name);

        this.threshold = threshold;
        this.logStream = logStream;
    }

    @Override
    public boolean isEnabledLevel(Level level) {
        return SimplifiedLog.isLoggable(level, threshold);
    }

    @Override
    public void log(Level level, Object msg, Throwable err) {
        if (isEnabledLevel(level)) {
            log(logStream, level, msg, err);
        }
    }

    public static void log(PrintStream logStream, Level level, Object msg) {
        log(logStream, level, msg, null);
    }

    public static void log(PrintStream logStream, Level level, Object msg, Throwable err) {
        Date now = new Date();
        String time;
        synchronized (LOG_TIME_FORMATTER) {
            time = LOG_TIME_FORMATTER.format(now);
        }
        logStream.append(time)
                .append(' ').append(level.getName())
                .append(' ').append(Thread.currentThread().getName())
                .append(' ').append(Objects.toString(msg))
                .println();
        printStackTrace(logStream, err);
    }

    /**
     * Looks for the {@link ConfigFileReaderSupport#LOG_LEVEL_CONFIG_PROP} in the options. If found, then uses it as the
     * result. Otherwise, invokes {@link #resolveLoggingVerbosity(String...)}
     *
     * @param  resolver The {@code -o} options specified by the user
     * @param  args     The command line arguments
     * @return          The resolved verbosity level
     */
    public static Level resolveLoggingVerbosity(PropertyResolver resolver, String... args) {
        String levelValue = PropertyResolverUtils.getString(
                resolver, ConfigFileReaderSupport.LOG_LEVEL_CONFIG_PROP);
        if (GenericUtils.isEmpty(levelValue)) {
            return resolveLoggingVerbosity(args);
        }

        LogLevelValue level = LogLevelValue.fromName(levelValue);
        if (level == null) {
            throw new IllegalArgumentException(
                    "Unknown " + ConfigFileReaderSupport.LOG_LEVEL_CONFIG_PROP + " option value: " + levelValue);
        }

        return level.getLoggingLevel();
    }

    public static Level resolveLoggingVerbosity(String... args) {
        return resolveLoggingVerbosity(args, GenericUtils.length(args));
    }

    public static Level resolveLoggingVerbosity(String[] args, int maxIndex) {
        for (int index = 0; index < maxIndex; index++) {
            String argName = args[index];
            if ("-v".equals(argName)) {
                return Level.INFO;
            } else if ("-vv".equals(argName)) {
                return Level.FINE;
            } else if ("-vvv".equals(argName)) {
                return Level.FINEST;
            }
        }

        return Level.CONFIG;
    }

    public static Logger resolveSystemLogger(Class<?> clazz, Level threshold) {
        return resolveSystemLogger(clazz.getName(), threshold);
    }

    public static Logger resolveSystemLogger(String name, Level threshold) {
        return resolveLogger(name, threshold, System.out, System.err);
    }

    public static Logger resolveLogger(Class<?> clazz, Level threshold, PrintStream stdout, PrintStream stderr) {
        return resolveLogger(clazz.getSimpleName(), threshold, stdout, stderr);
    }

    public static Logger resolveLogger(String name, Level threshold, PrintStream stdout, PrintStream stderr) {
        PrintStream logStream = resolvePrintStream(threshold, stdout, stderr);
        return getLogger(name, threshold, logStream);
    }

    public static boolean showError(PrintStream stderr, String message) {
        stderr.append("ERROR: ").println(message);
        return true;
    }

    public static boolean isEnabledVerbosityLogging(Level level) {
        if ((level == null) || Level.OFF.equals(level) || Level.CONFIG.equals(level)
                || Level.SEVERE.equals(level) || Level.WARNING.equals(level)) {
            return false;
        }

        return true;
    }

    public static PrintStream resolvePrintStream(Level threshold, PrintStream stdout, PrintStream stderr) {
        if (isEnabledVerbosityLogging(threshold)) {
            return Level.INFO.equals(threshold) ? stderr : stdout;
        } else {
            return NULL_PRINT_STREAM;
        }
    }

    public static <T extends Throwable> T printStackTrace(Appendable out, T reason) {
        if ((reason == null) || (out == null)) {
            return reason;
        }

        if (out instanceof PrintStream) {
            reason.printStackTrace((PrintStream) out);
        } else if (out instanceof PrintWriter) {
            reason.printStackTrace((PrintWriter) out);
        }

        return reason;
    }

    public static Logger getSystemLogger(Class<?> clazz, Level threshold) {
        return getSystemLogger(clazz.getName(), threshold);
    }

    public static Logger getSystemLogger(String name, Level threshold) {
        return getLogger(name, threshold, resolveSystemPrintStream(threshold));
    }

    public static PrintStream resolveSystemPrintStream(Level threshold) {
        return resolvePrintStream(threshold, System.out, System.err);
    }

    public static Logger getLogger(Class<?> clazz, Level threshold, PrintStream logStream) {
        return getLogger(clazz.getSimpleName(), threshold, logStream);
    }

    public static Logger getLogger(String name, Level threshold, PrintStream logStream) {
        return ((threshold == null) || Level.OFF.equals(threshold))
                ? SimplifiedLoggerSkeleton.EMPTY : new CliLogger(name, threshold, logStream);
    }
}
