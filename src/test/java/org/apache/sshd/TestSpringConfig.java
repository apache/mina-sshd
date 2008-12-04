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

import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.UserInfo;

public class TestSpringConfig {

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
        JSch sch = new JSch();
        sch.setLogger(new Logger() {
            public boolean isEnabled(int i) {
                return true;
            }

            public void log(int i, String s) {
                System.out.println("Log(jsch," + i + "): " + s);
            }
        });
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", 8000);
        s.setUserInfo(new UserInfo() {
            public String getPassphrase() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }
            public String getPassword() {
                return "smx";
            }
            public boolean promptPassword(String message) {
                return true;
            }
            public boolean promptPassphrase(String message) {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }
            public boolean promptYesNo(String message) {
                return true;
            }
            public void showMessage(String message) {
                //To change body of implemented methods use File | Settings | File Templates.
            }
        });
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
