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

import java.io.Closeable;
import java.io.OutputStream;
import java.io.InputStream;

/**
 * A client channel used to communicate with
 * the SSH server.  Client cannels can be shells,
 * simple commands or subsystems
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface ClientChannel extends Closeable {

    int TIMEOUT =     0x0001;
    int CLOSED =      0x0002;
    int STDOUT_DATA = 0x0004;
    int STDERR_DATA = 0x0008;
    int EOF =         0x0010;
    int EXIT_STATUS = 0x0020;
    int EXIT_SIGNAL = 0x0040;

    void setIn(InputStream in);

    void setOut(OutputStream out);

    void setErr(OutputStream err);

    void open() throws Exception;

    int waitFor(int mask, long timeout);

}
