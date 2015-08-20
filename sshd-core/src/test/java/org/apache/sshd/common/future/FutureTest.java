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
package org.apache.sshd.common.future;

import java.util.concurrent.TimeUnit;

import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FutureTest extends BaseTestSupport {
    public FutureTest() {
        super();
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testAwaitUnint() {
        final DefaultSshFuture future = new DefaultSshFuture(null);
        final Object expected = new Object();
        new Thread() {
            @Override
            public void run() {
                try {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(2L));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                future.setValue(expected);
            }
        }.start();

        future.awaitUninterruptibly();
        assertSame("Mismatched signalled value", expected, future.getValue());
    }
}
