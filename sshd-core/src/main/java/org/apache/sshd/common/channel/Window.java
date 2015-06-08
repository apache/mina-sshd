/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.AbstractLoggingBean;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * A Window for a given channel.
 * Windows are used to not overflow the client or server when sending datas.
 * Both clients and servers have a local and remote window and won't send
 * anymore data until the window has been expanded.  When the local window
 * is 
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Window extends AbstractLoggingBean {
    private final AbstractChannel channel;
    private final Object lock;
    private final String name;

    private int size;
    private int maxSize;
    private int packetSize;
    private boolean waiting;
    private boolean closed;
    private Map<String,?> props = Collections.<String,Object>emptyMap();

    public Window(AbstractChannel channel, Object lock, boolean client, boolean local) {
        this.channel = ValidateUtils.checkNotNull(channel, "No channel provided", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.lock = (lock != null) ? lock : this;
        this.name = String.valueOf(channel) + ": " + (client ? "client" : "server") + " " + (local ? "local " : "remote") + " window";
    }

    public Map<String,?> getProperties() {
        return props;
    }

    public int getSize() {
        synchronized (lock) {
            return size;
        }
    }

    public int getMaxSize() {
        return maxSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void init(Session session) {
        init(session.getFactoryManager());
    }
    
    public void init(FactoryManager manager) {
        init(manager.getProperties());
    }

    public void init(Map<String,?> props) {
        init(FactoryManagerUtils.getIntProperty(props, FactoryManager.WINDOW_SIZE, AbstractChannel.DEFAULT_WINDOW_SIZE),
             FactoryManagerUtils.getIntProperty(props, FactoryManager.MAX_PACKET_SIZE, AbstractChannel.DEFAULT_PACKET_SIZE),
             props);
    }

    public void init(int size, int packetSize, Map<String,?> props) {
        synchronized (lock) {
            this.size = size;
            this.maxSize = size;
            this.packetSize = packetSize;
            this.props = props;
            lock.notifyAll();
        }
    }

    public void expand(int window) {
        synchronized (lock) {
            size += window;
            if (log.isDebugEnabled()) {
                log.debug("Increase " + name + " by " + window + " up to " + size);
            }
            lock.notifyAll();
        }
    }

    public void consume(int len) {
        synchronized (lock) {
            //assert size > len;
            size -= len;
            if (log.isTraceEnabled()) {
                log.trace("Consume " + name + " by " + len + " down to " + size);
            }
        }
    }

    public void consumeAndCheck(int len) throws IOException {
        synchronized (lock) {
            //assert size > len;
            size -= len;
            if (log.isTraceEnabled()) {
                log.trace("Consume " + name + " by " + len + " down to " + size);
            }
            check(maxSize);
        }
    }

    public void check(int maxFree) throws IOException {
        synchronized (lock) {
            if (size < maxFree / 2) {
                if (log.isDebugEnabled()) {
                    log.debug("Increase " + name + " by " + (maxFree - size) + " up to " + maxFree);
                }
                channel.sendWindowAdjust(maxFree - size);
                size = maxFree;
            }
        }
    }

    public void waitAndConsume(int len) throws InterruptedException, WindowClosedException {
        synchronized (lock) {
            while (size < len && !closed) {
                if (log.isDebugEnabled()) {
                    log.debug("Waiting for {} bytes on {}", Integer.valueOf(len), name);
                }
                waiting = true;
                lock.wait();
            }
            if (waiting) {
                if (closed) {
                    log.debug("Window {} has been closed", name);
                } else {
                    log.debug("Space available for {}", name);
                }
                waiting = false;
            }
            if (closed) {
                throw new WindowClosedException(name);
            }
            size -= len;
            if (log.isTraceEnabled()) {
                log.trace("Consume " + name + " by " + len + " down to " + size);
            }
        }
    }

    public int waitForSpace() throws InterruptedException, WindowClosedException {
        synchronized (lock) {
            while (size == 0 && !closed) {
                log.debug("Waiting for some space on {}", name);
                waiting = true;
                lock.wait();
            }
            if (waiting) {
                if (closed) {
                    log.debug("Window {} has been closed", name);
                } else {
                    log.debug("Space available for {}", name);
                }
                waiting = false;
            }
            if (closed) {
                throw new WindowClosedException(name);
            }
            return size;
        }
    }

    public void notifyClosed() {
        synchronized (lock) {
            closed = true;
            if (waiting) {
                lock.notifyAll();
            }
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
