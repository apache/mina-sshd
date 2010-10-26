/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server.filesystem;

import java.io.File;
import java.io.FileFilter;

/**
 * <strong>Internal class, do not use directly.</strong>
 * 
 * FileFilter used for simple file name matching
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NameEqualsFileFilter implements FileFilter {

    private String nameToMatch;

    private boolean caseInsensitive = false;

    /**
     * Constructor
     * 
     * @param nameToMatch
     *            The exact file name to match
     * @param caseInsensitive
     *            Wether that match should be case insensitive
     */
    public NameEqualsFileFilter(final String nameToMatch,
            final boolean caseInsensitive) {
        this.nameToMatch = nameToMatch;
        this.caseInsensitive = caseInsensitive;
    }

    public boolean accept(final File file) {

        if (caseInsensitive) {
            return file.getName().equalsIgnoreCase(nameToMatch);
        } else {
            return file.getName().equals(nameToMatch);
        }
    }

}
