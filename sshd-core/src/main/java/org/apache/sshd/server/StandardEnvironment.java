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
package org.apache.sshd.server;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class StandardEnvironment extends AbstractLoggingBean implements Environment {
    private final Map<Signal, Collection<SignalListener>> listeners;
    private final Map<String, String> env;
    private final Map<PtyMode, Integer> ptyModes;

    public StandardEnvironment() {
        listeners = new ConcurrentHashMap<>(Signal.SIGNALS.size());
        env = new ConcurrentHashMap<>();
        ptyModes = new ConcurrentHashMap<>(PtyMode.MODES.size());
    }

    /*
     * NOTE: we don't care if the collection is a Set or not - after all, we hold the listeners inside a Set, so even if
     * we add several times the same listener to the same signal set, it is harmless
     */
    @Override
    public void addSignalListener(SignalListener listener, Collection<Signal> signals) {
        SignalListener.validateListener(listener);
        ValidateUtils.checkNotNullAndNotEmpty(signals, "No signals");

        for (Signal s : signals) {
            Collection<SignalListener> list = getSignalListeners(s, true);
            list.add(listener);
        }
    }

    @Override
    public Map<String, String> getEnv() {
        return env;
    }

    @Override
    public Map<PtyMode, Integer> getPtyModes() {
        return ptyModes;
    }

    @Override
    public void removeSignalListener(SignalListener listener) {
        if (listener == null) {
            return;
        }

        SignalListener.validateListener(listener);
        for (Signal s : Signal.SIGNALS) {
            Collection<SignalListener> ls = getSignalListeners(s, false);
            if (ls != null) {
                ls.remove(listener);
            }
        }
    }

    public void signal(Channel channel, Signal signal) {
        Collection<SignalListener> ls = getSignalListeners(signal, false);
        if (log.isDebugEnabled()) {
            log.debug("signal({})[{}] - listeners={}", channel, signal, ls);
        }

        if (GenericUtils.isEmpty(ls)) {
            return;
        }

        boolean traceEnabled = log.isTraceEnabled();
        for (SignalListener l : ls) {
            try {
                l.signal(channel, signal);

                if (traceEnabled) {
                    log.trace("signal({}) Signal {} to {}", channel, signal, l);
                }
            } catch (RuntimeException e) {
                log.warn("signal({}) Failed ({}) to signal {} to listener={}: {}",
                        channel, e.getClass().getSimpleName(), signal, l, e.getMessage());
            }
        }
    }

    /**
     * Adds a variable to the environment. This method is called <code>set</code> according to the name of the
     * appropriate posix command <code>set</code>
     *
     * @param key   environment variable name - never {@code null}/empty
     * @param value environment variable value
     */
    public void set(String key, String value) {
        // TODO: listening for property changes would be nice too.
        Map<String, String> environ = getEnv();
        environ.put(ValidateUtils.checkNotNullAndNotEmpty(key, "Empty environment variable name"), value);
    }

    /**
     * Retrieves the set of listeners registered for a signal
     *
     * @param  signal The specified {@link Signal}
     * @param  create If {@code true} and no current listeners are mapped then creates a new {@link Collection}
     * @return        The {@link Collection} of listeners registered for the signal - may be {@code null} in case
     *                <tt>create</tt> is {@code false}
     */
    protected Collection<SignalListener> getSignalListeners(Signal signal, boolean create) {
        Collection<SignalListener> ls = listeners.get(signal);
        if ((ls == null) && create) {
            synchronized (listeners) {
                ls = listeners.get(signal);
                if (ls == null) {
                    ls = new CopyOnWriteArraySet<>();
                    listeners.put(signal, ls);
                }
            }
        }

        return ls;
    }

    @Override
    public String toString() {
        return "env=" + getEnv() + ", modes=" + getPtyModes();
    }
}
