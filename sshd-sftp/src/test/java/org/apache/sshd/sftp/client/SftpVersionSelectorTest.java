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

package org.apache.sshd.sftp.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class SftpVersionSelectorTest extends JUnitTestSupport {
    public SftpVersionSelectorTest() {
        super();
    }

    @Test
    void currentVersionSelector() {
        List<Integer> available = new ArrayList<>();
        Random rnd = new Random(System.nanoTime());
        ClientSession session = Mockito.mock(ClientSession.class);
        for (int expected = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
             expected <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             expected++) {
            for (boolean initial : new boolean[] { true, false }) {
                assertEquals(expected,
                        SftpVersionSelector.CURRENT.selectVersion(session, initial, expected, available),
                        "Mismatched directly selected for initial=" + initial + "/available=" + available);
                available.add(expected);
            }
        }

        for (int expected = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
             expected <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             expected++) {
            for (boolean initial : new boolean[] { true, false }) {
                for (int index = 0; index < available.size(); index++) {
                    Collections.shuffle(available, rnd);
                    assertEquals(
                            expected, SftpVersionSelector.CURRENT.selectVersion(session, initial, expected,
                                    available),
                            "Mismatched suffling selected for initial=" + initial + ", current=" + expected
                                                + ", available=" + available);
                }
            }
        }
    }

    @Test
    void fixedVersionSelector() {
        final int fixedValue = 7365;
        testVersionSelector(SftpVersionSelector.fixedVersionSelector(fixedValue), fixedValue);
    }

    @Test
    void preferredVersionSelector() {
        List<Integer> available = new ArrayList<>();
        for (int version = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
             version <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             version++) {
            available.add(version);
        }

        List<Integer> preferred = new ArrayList<>(available);
        List<Integer> unavailable = Arrays.asList(7365, 3777347);
        Random rnd = new Random(System.nanoTime());
        ClientSession session = Mockito.mock(ClientSession.class);
        for (int index = 0; index < preferred.size(); index++) {
            Collections.shuffle(preferred, rnd);
            SftpVersionSelector selector = SftpVersionSelector.preferredVersionSelector(preferred);
            int expected = preferred.get(0);

            for (boolean initial : new boolean[] { true, false }) {
                for (int current = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
                     current <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
                     current++) {
                    assertEquals(
                            expected, selector.selectVersion(session, initial, current, available),
                            "Mismatched selected for current= " + current + ", available=" + available + ", preferred="
                                                                                                    + preferred);

                    try {
                        Collections.shuffle(unavailable, rnd);
                        int version = unavailable.get(0);
                        int actual = selector.selectVersion(session, initial, version, unavailable);
                        fail("Unexpected selected version (" + actual + ")"
                             + " for current= " + version
                             + ", available=" + unavailable
                             + ", preferred=" + preferred);
                    } catch (IllegalStateException e) {
                        // expected
                    }
                }
            }
        }
    }

    @Test
    void maximumVersionSelector() {
        testVersionSelector(SftpVersionSelector.MAXIMUM, SftpSubsystemEnvironment.HIGHER_SFTP_IMPL);
    }

    @Test
    void minimumVersionSelector() {
        testVersionSelector(SftpVersionSelector.MINIMUM, SftpSubsystemEnvironment.LOWER_SFTP_IMPL);
    }

    private static void testVersionSelector(SftpVersionSelector selector, int expected) {
        List<Integer> available = new ArrayList<>();
        for (int version = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
             version <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             version++) {
            available.add(version);
        }

        Random rnd = new Random(System.nanoTime());
        ClientSession session = Mockito.mock(ClientSession.class);
        for (int current = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
             current <= SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
             current++) {
            for (boolean initial : new boolean[] { true, false }) {
                for (int index = 0; index < available.size(); index++) {
                    assertEquals(expected, selector.selectVersion(session, initial, current, available),
                            "Mismatched selection for current=" + current + ", available=" + available);
                    Collections.shuffle(available, rnd);
                }
            }
        }
    }
}
