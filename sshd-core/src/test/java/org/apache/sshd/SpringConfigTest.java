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
package org.apache.sshd;

import java.io.OutputStream;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Test for spring based configuration.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SpringConfigTest extends BaseTest {

    private ClassPathXmlApplicationContext context;

    @Before
    public void setUp() throws Exception {
        context = new ClassPathXmlApplicationContext("classpath:spring.xml");
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            context.destroy();
        }
    }

    @Test
    public void testSpringConfig() throws Exception {
        int port = ((SshServer) context.getBean("sshServer")).getPort();

        JSchLogger.init();
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", port);
        s.setUserInfo(new SimpleUserInfo("smx"));
        s.connect();
        Channel c = s.openChannel("shell");
        c.connect();
        OutputStream os = c.getOutputStream();
        os.write("this is my command".getBytes());
        os.flush();
        Thread.sleep(100);
        c.disconnect();
        s.disconnect();
    }


}
