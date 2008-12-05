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
package org.apache.sshd.server.pam;

import org.apache.sshd.server.PasswordAuthenticator;
import net.sf.jpam.Pam;
import net.sf.jpam.PamReturnValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A password authenticator using PAM (Pluggable Authentication Module).
 * Such an authenticator can be used to integrate into an Unix operating
 * system. 
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class PAMPasswordAuthenticator implements PasswordAuthenticator {

    private static final Logger LOG = LoggerFactory.getLogger(PAMPasswordAuthenticator.class);

    private String service = "sshd";

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public Object authenticate(String username, String password) {
        LOG.info("Authenticating user {} using PAM", username);
        PamReturnValue val = new Pam(service).authenticate(username, password);
        LOG.info("Result: {}", val);
        if (PamReturnValue.PAM_SUCCESS.equals(val)) {
            return username;
        }
        return null;
    }
}
