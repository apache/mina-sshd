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
package org.apache.sshd.spring;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Test for spring based configuration.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SpringConfigTest extends BaseTestSupport {

    private ClassPathXmlApplicationContext context;

    public SpringConfigTest() {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        Class<?> clazz = getClass();
        Package pkg = clazz.getPackage();
        context = new ClassPathXmlApplicationContext(
                "classpath:" + pkg.getName().replace('.', '/') + "/" + clazz.getSimpleName() + ".xml");
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            context.close();
        }
    }

    @Test
    public void testSpringConfig() throws Exception {
        SshServer server = CoreTestSupportUtils.setupTestFullSupportServer(context.getBean(SshServer.class));
        int port = server.getPort();

        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, port);
        s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
        s.connect();

        try {
            Channel c = s.openChannel(org.apache.sshd.common.channel.Channel.CHANNEL_SHELL);
            c.connect();

            String command = OsUtils.isWin32() ? "dir" : "ls";
            try (OutputStream os = c.getOutputStream()) {
                os.write(command.getBytes(StandardCharsets.UTF_8));
                os.flush();
                Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
            } finally {
                c.disconnect();
            }
        } finally {
            s.disconnect();
        }
    }
}
