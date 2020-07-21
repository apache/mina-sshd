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

package org.apache.sshd.sftp.client.extensions;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.sshd.sftp.common.extensions.VersionsParser.Versions;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class VersionParserTest extends JUnitTestSupport {
    public VersionParserTest() {
        super();
    }

    @Test // see SSHD-909
    public void testIgnoreNonNumbersWhenResolvingAvailableVersions() {
        List<Integer> expected = Arrays.asList(3, 4, 5, 6);
        List<String> values = expected.stream()
                .map(Object::toString)
                .collect(Collectors.toList());
        values.addAll(Arrays.asList(
                "draft-ietf-secsh-filexfer-11@vandyke.com", "partial-v6@vandyke.com"));
        Versions v = new Versions(values);
        List<Integer> actual = v.resolveAvailableVersions(3);
        assertListEquals(getCurrentTestName(), expected, actual);
    }
}
