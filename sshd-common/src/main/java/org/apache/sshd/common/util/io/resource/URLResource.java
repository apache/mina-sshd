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

package org.apache.sshd.common.util.io.resource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class URLResource extends AbstractIoResource<URL> {
    public URLResource(URL url) {
        super(URL.class, url);
    }

    public URL getURL() {
        return getResourceValue();
    }

    @Override
    public String getName() {
        URL url = getURL();
        // URL#toString() may involve a DNS lookup
        return url.toExternalForm();
    }

    @Override
    public InputStream openInputStream() throws IOException {
        URL url = getURL();
        return url.openStream();
    }
}
