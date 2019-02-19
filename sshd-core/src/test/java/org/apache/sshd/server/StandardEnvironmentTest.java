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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class StandardEnvironmentTest extends BaseTestSupport {
    public StandardEnvironmentTest() {
        super();
    }

    @Test
    public void testAddSignalListenerOnDuplicateSignals() {
        StandardEnvironment environ = new StandardEnvironment();
        SignalListener listener = (channel, signal) -> {
            // ignored
        };

        for (Signal s : Signal.SIGNALS) {
            environ.addSignalListener(listener, s, s, s, s, s, s);

            Collection<SignalListener> ls = environ.getSignalListeners(s, false);
            assertEquals("Mismatched registered listeners count for signal=" + s, 1, GenericUtils.size(ls));
        }
    }
}
