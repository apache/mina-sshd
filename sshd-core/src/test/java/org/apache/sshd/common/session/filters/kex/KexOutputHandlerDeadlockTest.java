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
package org.apache.sshd.common.session.filters.kex;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Reproduces a self-deadlock in {@link KexOutputHandler} caused by an illegal read-to-write lock upgrade on its
 * {@link java.util.concurrent.locks.ReentrantReadWriteLock}.
 * <p>
 * The single-thread cycle (see the offending frames in production thread dumps):
 * </p>
 * <ol>
 * <li>An outgoing high-level packet (e.g. {@code SSH_MSG_CHANNEL_CLOSE}) enters
 * {@link KexOutputHandler#send(int, Buffer)} &rarr; {@code writeOrEnqueue()}, which acquires the <b>read lock</b>
 * ({@code KexOutputHandler.java:259}) and, KEX being done, performs the actual write via {@code filter.write()}
 * ({@code KexOutputHandler.java:268}).</li>
 * <li>The nio2 transport can complete/fail that write <b>inline on the calling thread</b>
 * ({@code sun.nio.ch.Invoker.invokeDirect}). On failure the session is closed, whose teardown runs
 * {@code SshTransportFilter.shutdown} &rarr; {@link KexFilter#shutdown()} &rarr; {@link KexOutputHandler#shutdown()}
 * ({@code KexFilter.java:342}).</li>
 * <li>{@link KexOutputHandler#shutdown()} calls {@code updateState()} which acquires the <b>write lock</b>
 * ({@code KexOutputHandler.java:146}) &mdash; while the same thread still holds the read lock from step&nbsp;1.
 * {@code ReentrantReadWriteLock} does not allow upgrading, so the thread parks forever holding its own read lock.</li>
 * </ol>
 * <p>
 * The test mocks {@link KexFilter} so that {@code filter.write(...)} performs the terminal action of that inline
 * teardown chain &mdash; {@code output.shutdown()} (exactly what {@link KexFilter#shutdown()} does) &mdash; on the
 * calling thread, faithfully recreating the reentrancy without a real socket.
 * <p>
 * This is a regression test: it currently <b>fails</b> (the worker deadlocks and never returns), and must <b>pass</b>
 * once the upgrade is avoided.
 */
@Tag("NoIoTestCase")
class KexOutputHandlerDeadlockTest {

    KexOutputHandlerDeadlockTest() {
        super();
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void readToWriteLockUpgradeSelfDeadlockOnInlineWriteFailure() throws Exception {
        KexFilter filter = mock(KexFilter.class);
        AbstractSession session = mock(AbstractSession.class);
        when(filter.getSession()).thenReturn(session);
        // KEX finished: writeOrEnqueue() takes the direct-write branch through filter.write().
        when(filter.getKexState()).thenReturn(new AtomicReference<>(KexState.DONE));

        KexOutputHandler output = new KexOutputHandler(filter, LoggerFactory.getLogger(KexOutputHandlerDeadlockTest.class));

        // Model the nio2 write-failure callback firing inline on the calling thread: the real chain is
        // filter.write() -> ... -> Nio2Session.onFailed -> session close -> SshTransportFilter.shutdown ->
        // KexFilter.shutdown() -> KexOutputHandler.shutdown(). We invoke the terminal call directly, on the
        // same thread, while writeOrEnqueue() still holds the read lock.
        when(filter.write(anyInt(), any(Buffer.class))).thenAnswer(invocation -> {
            output.shutdown();
            return null;
        });

        Thread worker = new Thread(() -> {
            try {
                Buffer buffer = new ByteArrayBuffer(new byte[] { (byte) SshConstants.SSH_MSG_CHANNEL_CLOSE });
                output.send(SshConstants.SSH_MSG_CHANNEL_CLOSE, buffer);
            } catch (IOException e) {
                // Not expected on this path; the thread deadlocks before returning.
            }
        }, "kex-deadlock-worker");
        worker.setDaemon(true);
        worker.start();

        worker.join(TimeUnit.SECONDS.toMillis(5));

        if (worker.isAlive()) {
            StackTraceElement[] stack = worker.getStackTrace();
            String rendered = Stream.of(stack).map(e -> "\tat " + e).reduce("", (a, b) -> a + '\n' + b);
            boolean parkedOnWriteLock = Stream.of(stack).anyMatch(
                    e -> "java.util.concurrent.locks.ReentrantReadWriteLock$WriteLock".equals(e.getClassName())
                            && "lock".equals(e.getMethodName()));
            boolean viaShutdownUpdateState
                    = Stream.of(stack).anyMatch(e -> e.toString().contains("KexOutputHandler.updateState"))
                            && Stream.of(stack).anyMatch(e -> e.toString().contains("KexOutputHandler.shutdown"));
            boolean readLockStillHeldViaWriteOrEnqueue = Stream.of(stack)
                    .anyMatch(e -> e.toString().contains("KexOutputHandler.writeOrEnqueue"));
            fail("KexOutputHandler.send() deadlocked: read-to-write lock upgrade in KexOutputHandler."
                 + " parkedOnWriteLock=" + parkedOnWriteLock
                 + ", shutdown()->updateState()=" + viaShutdownUpdateState
                 + ", readLockHeldViaWriteOrEnqueue=" + readLockStillHeldViaWriteOrEnqueue
                 + "\nWorker stack:" + rendered);
        }
        // Reaching here means send() returned: the upgrade no longer happens and the bug is fixed.
    }
}
