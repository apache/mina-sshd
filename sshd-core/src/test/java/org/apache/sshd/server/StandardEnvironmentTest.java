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

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class StandardEnvironmentTest extends BaseTestSupport {
    public StandardEnvironmentTest() {
        super();
    }

    @Test
    void addSignalListenerOnDuplicateSignals() {
        StandardEnvironment environ = new StandardEnvironment();
        SignalListener listener = (channel, signal) -> {
            // ignored
        };

        for (Signal s : Signal.SIGNALS) {
            environ.addSignalListener(listener, s, s, s, s, s, s);

            Collection<SignalListener> ls = environ.getSignalListeners(s, false);
            assertEquals(1, GenericUtils.size(ls), "Mismatched registered listeners count for signal=" + s);
        }
    }
}
