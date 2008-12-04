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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Window {

    private final static Logger log = LoggerFactory.getLogger(Window.class);

    private final AbstractChannel channel;
    private final Object lock;
    private final String name;

    private int size;
    private int maxSize;
    private int packetSize;
    private boolean waiting;

    public Window(AbstractChannel channel, Object lock, boolean client, boolean local) {
        this.channel = channel;
        this.lock = lock != null ? lock : this;
        this.name = (client ? "client" : "server") + " " + (local ? "local " : "remote") + " window";
    }

    public int getSize() {
        return size;
    }

    public int getMaxSize() {
        return maxSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void init(int size, int packetSize) {
        this.size = size;
        this.maxSize = size;
        this.packetSize = packetSize;
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
        int threshold = Math.min(packetSize * 8, maxSize / 4);
        synchronized (lock) {
            if ((maxFree - size) > packetSize && (maxFree - size > threshold || size < threshold)) {
                if (log.isDebugEnabled()) {
                    log.debug("Increase " + name + " by " + (maxFree - size) + " up to " + maxFree);
                }
                channel.sendWindowAdjust(maxFree - size);
                size = maxFree;
            }
        }
    }

    public void waitAndConsume(int len) throws InterruptedException {
        synchronized (lock) {
            while (size < len) {
                log.debug("Waiting for {} bytes on {}", len, name);
                waiting = true;
                lock.wait();
            }
            if (waiting) {
                log.debug("Space available for {}", name);
                waiting = false;
            }
            size -= len;
            if (log.isTraceEnabled()) {
                log.trace("Consume " + name + " by " + len + " down to " + size);
            }
        }
    }

}
