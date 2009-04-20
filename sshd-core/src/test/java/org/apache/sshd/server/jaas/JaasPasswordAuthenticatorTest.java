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
package org.apache.sshd.server.jaas;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;

import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import static org.junit.Assert.*;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev: 728050 $, $Date: 2008-12-19 16:50:58 +0100 (Fri, 19 Dec 2008) $
 */
public class JaasPasswordAuthenticatorTest {

    @Before
    public void setUp() {
        Configuration config = new Configuration() {
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] {
                        new AppConfigurationEntry(DummyLoginModule.class.getName(),
                                                  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                                  new HashMap<String,Object>())
                };
            }
            public void refresh() {
            }
        };
        Configuration.setConfiguration(config);
    }

    @After
    public void tearDown() {
        Configuration.setConfiguration(null);
    }

    @Test
    public void testAuthenticator() {
        JaasPasswordAuthenticator auth = new JaasPasswordAuthenticator();
        assertNull(auth.getDomain());
        auth.setDomain("domain");
        assertEquals("domain", auth.getDomain());
        assertNotNull(auth.authenticate("sshd", "sshd"));
        assertNull(auth.authenticate("sshd", "dummy"));
    }


    protected static class DummyLoginModule implements LoginModule {

        private Subject subject;
        private CallbackHandler callbackHandler;

        public DummyLoginModule() {
        }

        public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
            this.subject = subject;
            this.callbackHandler = callbackHandler;
        }

        public boolean login() throws LoginException {
            Callback[] callbacks = new Callback[2];
            callbacks[0] = new NameCallback("Username: ");
            callbacks[1] = new PasswordCallback("Password: ", false);
            try {
                callbackHandler.handle(callbacks);
            } catch (IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException(uce.getMessage() + " not available to obtain information from user");
            }
            String user = ((NameCallback) callbacks[0]).getName();
            char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
            return user.equals(new String(tmpPassword));
        }

        public boolean commit() throws LoginException {
            return true;
        }

        public boolean abort() throws LoginException {
            return true;
        }

        public boolean logout() throws LoginException {
            return true;
        }
    }
}
