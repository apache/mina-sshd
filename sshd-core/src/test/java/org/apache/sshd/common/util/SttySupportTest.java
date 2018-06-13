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
package org.apache.sshd.common.util;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.channel.SttySupport;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SttySupportTest extends BaseTestSupport {
    public SttySupportTest() {
        super();
    }

    @Test
    public void parseOutput1() throws Exception {
        Reader r = new InputStreamReader(getClass().getResourceAsStream("stty-output-1.txt"), StandardCharsets.UTF_8);
        char[] buf = new char[8192];
        int len = r.read(buf);
        String stty = new String(buf, 0, len);
        Map<PtyMode, Integer> modes = SttySupport.parsePtyModes(stty);
        System.err.println(modes);
    }

    @Test
    public void parseOutput2() throws Exception {
        Reader r = new InputStreamReader(getClass().getResourceAsStream("stty-output-2.txt"), StandardCharsets.UTF_8);
        char[] buf = new char[8192];
        int len = r.read(buf);
        String stty = new String(buf, 0, len);
        Map<PtyMode, Integer> modes = SttySupport.parsePtyModes(stty);
        System.err.println(modes);
    }
}
