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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.logging.Level;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class LoggingUtils {
    /**
     * Default value used for {@link #logExceptionStackTrace(Logger, Level, Throwable) logExceptionStackTrace}
     * unless {@link #setDefaultStackTraceLoggingDepth(int) overridden}
     */
    public static final int DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE = Byte.SIZE;

    private static final AtomicInteger DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE_HOLDER =
        new AtomicInteger(DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE);

    private LoggingUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * Scans using reflection API for all fields that are {@code public static final}
     * that start with the given common prefix (case <U>sensitive</U>) and are of type
     * {@link Number}.
     *
     * @param clazz The {@link Class} to query
     * @param commonPrefix The expected common prefix
     * @return A {@link Map} of all the matching fields, where key=the field's {@link Integer}
     * value and mapping=the field's name
     * @see #generateMnemonicMap(Class, Predicate)
     */
    public static Map<Integer, String> generateMnemonicMap(Class<?> clazz, final String commonPrefix) {
        return generateMnemonicMap(clazz, f -> {
            String name = f.getName();
            return name.startsWith(commonPrefix);
        });
    }

    /**
     * Scans using reflection API for all <U>numeric {@code public static final}</U> fields
     * that are also accepted by the predicate. Any field that is not such or fail to retrieve
     * its value, or has a duplicate value is <U>silently</U> skipped.
     *
     * @param clazz The {@link Class} to query
     * @param acceptor The {@link Predicate} used to decide whether to process the {@link Field}
     * (besides being a {@link Number} and {@code public static final}).
     * @return A {@link Map} of all the matching fields, where key=the field's {@link Integer}
     * value and mapping=the field's name
     * @see #getMnemonicFields(Class, Predicate)
     */
    public static Map<Integer, String> generateMnemonicMap(Class<?> clazz, Predicate<? super Field> acceptor) {
        Collection<Field> fields = getMnemonicFields(clazz, acceptor);
        if (GenericUtils.isEmpty(fields)) {
            return Collections.emptyMap();
        }

        Map<Integer, String> result = new TreeMap<>(Comparator.naturalOrder());
        for (Field f : fields) {
            String name = f.getName();
            try {
                Number value = (Number) f.get(null);
                String prev = result.put(NumberUtils.toInteger(value), name);
                if (prev != null) {
                    //noinspection UnnecessaryContinue
                    continue;   // debug breakpoint
                }
            } catch (Exception e) {
                //noinspection UnnecessaryContinue
                continue;   // debug breakpoint
            }
        }

        return result;
    }

    /**
     * Scans using reflection API for all <U>numeric {@code public static final}</U> fields
     * that have a common prefix and whose value is used by several of the other
     * matching fields
     *
     * @param clazz The {@link Class} to query
     * @param commonPrefix The expected common prefix
     * @return A {@link Map} of all the mnemonic fields names whose value is the same as other
     * fields in this map. The key is the field's name and value is its associated opcode.
     * @see #getAmbiguousMenmonics(Class, Predicate)
     */
    public static Map<String, Integer> getAmbiguousMenmonics(Class<?> clazz, String commonPrefix) {
        return getAmbiguousMenmonics(clazz, f -> {
            String name = f.getName();
            return name.startsWith(commonPrefix);
        });
    }

    /**
     * Scans using reflection API for all <U>numeric {@code public static final}</U> fields
     * that are also accepted by the predicate and whose value is used by several of the other
     * matching fields
     *
     * @param clazz The {@link Class} to query
     * @param acceptor The {@link Predicate} used to decide whether to process the {@link Field}
     * (besides being a {@link Number} and {@code public static final}).
     * @return A {@link Map} of all the mnemonic fields names whose value is the same as other
     * fields in this map. The key is the field's name and value is its associated opcode.
     * @see #getMnemonicFields(Class, Predicate)
     */
    public static Map<String, Integer> getAmbiguousMenmonics(Class<?> clazz, Predicate<? super Field> acceptor) {
        Collection<Field> fields = getMnemonicFields(clazz, acceptor);
        if (GenericUtils.isEmpty(fields)) {
            return Collections.emptyMap();
        }

        Map<String, Integer> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<Integer, List<String>> opcodesMap = new TreeMap<>(Comparator.naturalOrder());
        for (Field f : fields) {
            String name = f.getName();
            try {
                Number value = (Number) f.get(null);
                Integer key = NumberUtils.toInteger(value);
                List<String> nameList = opcodesMap.get(key);
                if (nameList == null) {
                    nameList = new ArrayList<>();
                    opcodesMap.put(key, nameList);
                }
                nameList.add(name);

                int numOpcodes = nameList.size();
                if (numOpcodes > 1) {
                    result.put(name, key);
                    if (numOpcodes == 2) {  // add the 1st name as well
                        result.put(nameList.get(0), key);
                    }
                }
            } catch (Exception e) {
                continue;   // debug breakpoint
            }
        }

        return result;
    }

    /**
     * Scans using reflection API for all <U>numeric {@code public static final}</U> fields
     * that are also accepted by the predicate.
     *
     * @param clazz The {@link Class} to query
     * @param acceptor The {@link Predicate} used to decide whether to process the {@link Field}
     * (besides being a {@link Number} and {@code public static final}).
     * @return A {@link Collection} of all the fields that have satisfied all conditions
     */
    public static Collection<Field> getMnemonicFields(Class<?> clazz, Predicate<? super Field> acceptor) {
        return ReflectionUtils.getMatchingFields(clazz, f -> {
            int mods = f.getModifiers();
            if ((!Modifier.isPublic(mods)) || (!Modifier.isStatic(mods)) || (!Modifier.isFinal(mods))) {
                return false;
            }

            Class<?> type = f.getType();
            if (!NumberUtils.isNumericClass(type)) {
                return false;
            }

            return acceptor.test(f);
        });
    }

    /**
     * Verifies if the given level is above the required threshold for logging.
     *
     * @param level     The {@link Level} to evaluate
     * @param threshold The threshold {@link Level}
     * @return {@code true} if the evaluated level is above the required
     * threshold.
     * <P>
     * <B>Note(s):</B>
     * </P>
     * <UL>
     * <LI><P>
     * If either argument is {@code null} then result is {@code false}.
     * </P></LI>
     *
     * <LI><P>
     * If the evaluated level is {@link Level#OFF} then result is {@code false}
     * regardless of the threshold.
     * </P></LI>
     *
     * <LI><P>
     * If the threshold is {@link Level#ALL} and the evaluated level is
     * <U>not</U> {@link Level#OFF} the result is {@code true}.
     * </P></LI>
     *
     * <LI><P>
     * Otherwise, the evaluated level {@link Level#intValue()} must be
     * greater or equal to the threshold.
     * </P></LI>
     * </UL>
     */
    public static boolean isLoggable(Level level, Level threshold) {
        if ((level == null) || (threshold == null)) {
            return false;
        } else if (Level.OFF.equals(level) || Level.OFF.equals(threshold)) {
            return false;
        } else if (Level.ALL.equals(threshold)) {
            return true;
        } else {
            return level.intValue() >= threshold.intValue();
        }
    }

    public static SimplifiedLog wrap(final Logger logger) {
        if (logger == null) {
            return SimplifiedLog.EMPTY;
        } else {
            return new SimplifiedLog() {
                @Override
                public void log(Level level, Object message, Throwable t) {
                    if (isEnabled(level)) {
                        logMessage(logger, level, message, t);
                    }

                }

                @Override
                public boolean isEnabled(Level level) {
                    return isLoggable(logger, level);
                }
            };
        }
    }

    // NOTE: assume that level enabled has been checked !!!
    public static void logMessage(Logger logger, Level level, Object message, Throwable t) {
        if ((logger == null) || (level == null) || Level.OFF.equals(level)) {
            return;
        } else if (Level.SEVERE.equals(level)) {
            logger.error(Objects.toString(message), t);
        } else if (Level.WARNING.equals(level)) {
            logger.warn(Objects.toString(message), t);
        } else if (Level.INFO.equals(level) || Level.ALL.equals(level)) {
            logger.info(Objects.toString(message), t);
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            logger.debug(Objects.toString(message), t);
        } else {
            logger.trace(Objects.toString(message), t);
        }
    }

    /**
     * @param logger The {@link Logger} instance - ignored if {@code null}
     * @param level  The validate log {@link Level} - ignored if {@code null}
     * @return <P>{@code true} if the level is enabled for the logger. The
     * mapping of the level to the logger is as follows:</P>
     * <UL>
     * <LI>{@link Level#OFF} always returns {@code false}</LI>
     * <LI>{@link Level#SEVERE} returns {@link Logger#isErrorEnabled()}</LI>
     * <LI>{@link Level#WARNING} returns {@link Logger#isWarnEnabled()}</LI>
     * <LI>{@link Level#INFO} and {@link Level#ALL} returns {@link Logger#isInfoEnabled()}</LI>
     * <LI>{@link Level#CONFIG} and {@link Level#FINE} returns {@link Logger#isDebugEnabled()}</LI>
     * <LI>All other levels return {@link Logger#isTraceEnabled()}</LI>
     * </UL>
     */
    public static boolean isLoggable(Logger logger, Level level) {
        if ((logger == null) || (level == null) || Level.OFF.equals(level)) {
            return false;
        } else if (Level.SEVERE.equals(level)) {
            return logger.isErrorEnabled();
        } else if (Level.WARNING.equals(level)) {
            return logger.isWarnEnabled();
        } else if (Level.INFO.equals(level) || Level.ALL.equals(level)) {
            return logger.isInfoEnabled();
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            return logger.isDebugEnabled();
        } else {
            return logger.isTraceEnabled();
        }
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param level The log {@link Level} mapped as follows:</BR>
     *
     * <UL>
     *     <LI>{@link Level#OFF} - {@link #nologClosure(Logger)}</LI>
     *     <LI>{@link Level#SEVERE} - {@link #errorClosure(Logger)}</LI>
     *     <LI>{@link Level#WARNING} - {@link #warnClosure(Logger)}</LI>
     *     <LI>{@link Level#INFO}/{@link Level#ALL} - {@link #infoClosure(Logger)}</LI>
     *     <LI>{@link Level#CONFIG}/{@link Level#FINE} - {@link #debugClosure(Logger)}</LI>
     *     <LI>All others - {@link #traceClosure(Logger)}</LI>
     * </UL>
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if the specific level is enabled
     */
    public static <T> Consumer<T> loggingClosure(Logger logger, Level level) {
        return loggingClosure(logger, level, null);
    }

    public static <T> Consumer<T> loggingClosure(Logger logger, Level level, Throwable t) {
        Objects.requireNonNull(level, "No level provided");

        if (Level.OFF.equals(level)) {
            return nologClosure(logger);
        } else if (Level.SEVERE.equals(level)) {
            return errorClosure(logger, t);
        } else if (Level.WARNING.equals(level)) {
            return warnClosure(logger, t);
        } else if (Level.INFO.equals(level) || Level.ALL.equals(level)) {
            return infoClosure(logger, t);
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            return debugClosure(logger, t);
        } else {
            return traceClosure(logger, t);
        }
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs nothing when invoked
     */
    public static <T> Consumer<T> nologClosure(Logger logger) {
        Objects.requireNonNull(logger, "No logger provided");
        return t -> { /* do nothing */ };
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isErrorEnabled()}
     */
    public static <T> Consumer<T> errorClosure(Logger logger) {
        return errorClosure(logger, null);
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param thrown A {@link Throwable} to attach to the message - ignored if {@code null}
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isErrorEnabled()}
     */
    public static <T> Consumer<T> errorClosure(Logger logger, Throwable thrown) {
        Objects.requireNonNull(logger, "No logger provided");
        return new Consumer<T>() {
            @Override
            public void accept(T input) {
                if (logger.isErrorEnabled()) {
                    String msg = String.valueOf(input);
                    if (thrown == null) {
                        logger.error(msg);
                    } else {
                        logger.error(msg, thrown);
                    }
                }
            }

            @Override
            public String toString() {
                return "ERROR";
            }
        };
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isWarnEnabled()}
     */
    public static <T> Consumer<T> warnClosure(Logger logger) {
        return warnClosure(logger, null);
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param thrown A {@link Throwable} to attach to the message - ignored if {@code null}
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the {@link String#valueOf(Object)}
     * value of its argument if {@link Logger#isWarnEnabled()}
     */
    public static <T> Consumer<T> warnClosure(Logger logger, Throwable thrown) {
        Objects.requireNonNull(logger, "No logger provided");
        return new Consumer<T>() {
            @Override
            public void accept(T input) {
                if (logger.isWarnEnabled()) {
                    String msg = String.valueOf(input);
                    if (thrown == null) {
                        logger.warn(msg);
                    } else {
                        logger.warn(msg, thrown);
                    }
                }
            }

            @Override
            public String toString() {
                return "WARN";
            }
        };
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the {@link String#valueOf(Object)}
     * value of its argument if {@link Logger#isInfoEnabled()}
     */
    public static <T> Consumer<T> infoClosure(Logger logger) {
        return infoClosure(logger, null);
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param thrown A {@link Throwable} to attach to the message - ignored if {@code null}
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isInfoEnabled()}
     */
    public static <T> Consumer<T> infoClosure(Logger logger, Throwable thrown) {
        Objects.requireNonNull(logger, "No logger provided");
        return new Consumer<T>() {
            @Override
            public void accept(T input) {
                if (logger.isInfoEnabled()) {
                    String msg = String.valueOf(input);
                    if (thrown == null) {
                        logger.info(msg);
                    } else {
                        logger.info(msg, thrown);
                    }
                }
            }

            @Override
            public String toString() {
                return "INFO";
            }
        };
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isDebugEnabled()}
     */
    public static <T> Consumer<T> debugClosure(Logger logger) {
        return debugClosure(logger, null);
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param thrown A {@link Throwable} to attach to the message - ignored if {@code null}
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isDebugEnabled()}
     */
    public static <T> Consumer<T> debugClosure(Logger logger, Throwable thrown) {
        Objects.requireNonNull(logger, "No logger provided");
        return new Consumer<T>() {
            @Override
            public void accept(T input) {
                if (logger.isDebugEnabled()) {
                    String msg = String.valueOf(input);
                    if (thrown == null) {
                        logger.debug(msg);
                    } else {
                        logger.debug(msg, thrown);
                    }
                }
            }

            @Override
            public String toString() {
                return "DEBUG";
            }
        };
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isTraceEnabled()}
     */
    public static <T> Consumer<T> traceClosure(Logger logger) {
        return traceClosure(logger, null);
    }

    /**
     * @param <T> Generic message type consumer
     * @param logger The {@link Logger} instance to use
     * @param thrown A {@link Throwable} to attach to the message - ignored if {@code null}
     * @return A consumer whose {@link Consumer#accept(Object)} method logs the
     * {@link String#valueOf(Object)} value of its argument if {@link Logger#isTraceEnabled()}
     */
    public static <T> Consumer<T> traceClosure(Logger logger, Throwable thrown) {
        Objects.requireNonNull(logger, "No logger provided");
        return new Consumer<T>() {
            @Override
            public void accept(T input) {
                if (logger.isTraceEnabled()) {
                    String msg = String.valueOf(input);
                    if (thrown == null) {
                        logger.trace(msg);
                    } else {
                        logger.trace(msg, thrown);
                    }
                }
            }

            @Override
            public String toString() {
                return "TRACE";
            }
        };
    }

    /**
     * Logs the stack trace of the exception up to {@link #getDefaultStackTraceLoggingDepth() default depth}
     * or available stack trace elements.
     *
     * @param logger The {@link Logger} instance to log the information
     * @param level The logging {@link Level} to use
     * @param t The {@link Throwable} data to write - ignored if {@code null}
     */
    public static void logExceptionStackTrace(Logger logger, Level level, Throwable t) {
        logExceptionStackTrace(logger, level, t, getDefaultStackTraceLoggingDepth());
    }

    /**
     * Logs the stack trace of the exception up to specified depth or available stack trace elements.
     *
     * @param logger The {@link Logger} instance to log the information
     * @param level The logging {@link Level} to use
     * @param t The {@link Throwable} data to write - ignored if {@code null}
     * @param maxDepth Maximum stack trace elements to log - if non-positive then nothing is logged
     */
    public static void logExceptionStackTrace(Logger logger, Level level, Throwable t, int maxDepth) {
        if ((t == null) || (maxDepth <= 0) || (!isLoggable(logger, level))) {
            return;
        }

        Consumer<String> executor = loggingClosure(logger, level);
        logExceptionStackTrace(t, maxDepth, executor);
    }

    /**
     * Logs the stack trace of the exception up to specified depth or available stack trace elements.
     *
     * @param t The {@link Throwable} data to write - ignored if {@code null}
     * @param maxDepth Maximum stack trace elements to log - if non-positive then nothing is logged
     * @param executor The {@link Consumer} invoked for each formatted stack trace element
     */
    public static void logExceptionStackTrace(Throwable t, int maxDepth, Consumer<? super String> executor) {
        if ((t == null) || (maxDepth <= 0) || (executor == null)) {
            return;
        }
        StackTraceElement[] elements = t.getStackTrace();
        int numElements = GenericUtils.length(elements);
        StringBuilder workBuf = new StringBuilder(Byte.MAX_VALUE);
        for (int index = 0, maxElements = Math.min(maxDepth, numElements); index < maxElements; index++) {
            StackTraceElement ste = elements[index];
            workBuf.setLength(0); // re-use
            try {
                appendStackTraceElement(workBuf.append("    at "), ste);
            } catch (IOException e) {
                throw new RuntimeException("Unexpected failure (" + e.getClass().getSimpleName() + ")" + " to append stack-trace-element=" + ste + ": " + e.getMessage(), e);
            }
            executor.accept(workBuf.toString());
        }
    }

    /**
     * @return The default value used by {@link #logExceptionStackTrace(Logger, Level, Throwable)}
     */
    public static int getDefaultStackTraceLoggingDepth() {
        return Math.max(DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE_HOLDER.get(), DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE);
    }

    /**
     * @param value The value to set - <B>Note:</B> the effective value is the <U>maximum</U>
     * between it and {@value #DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE}
     */
    public static void setDefaultStackTraceLoggingDepth(int value) {
        DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE_HOLDER.set(Math.max(value, DEFAULT_STACK_TRACE_LOGGING_DEPTH_VALUE));
    }

    /**
     * Generates a result very similar to {@link StackTraceElement#toString()}
     *
     * @param <A> The {@link Appendable} target type
     * @param sb The target appender
     * @param ste The {@link StackTraceElement} to append - ignored if {@code null}
     * @return The updated appender instance
     * @throws IOException If failed to append the data
     */
    public static <A extends Appendable> A appendStackTraceElement(A sb, StackTraceElement ste) throws IOException {
        if (ste == null) {
            return sb;
        }

        sb.append(ste.getClassName()).append('.').append(ste.getMethodName());
        if (ste.isNativeMethod()) {
            sb.append("(Native Method)");
            return sb;
        }

        sb.append('(');

        String fileName = ste.getFileName();
        sb.append(GenericUtils.isEmpty(fileName) ? "Unknown Source" : fileName);

        int lineNumber = ste.getLineNumber();
        if (lineNumber >= 0) {
            sb.append(':').append(Integer.toString(lineNumber));
        }
        sb.append(')');

        return sb;
    }
}
