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
package org.apache.sshd.common.file.root;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/**
 * Utility functions for rooted file utils
 */
public final class RootedFileSystemUtils {

    private RootedFileSystemUtils() {
        // do not construct
    }

    /**
     * Validate that the relative path target is safe. This means that at no point in the path can there be more ".."
     * than path parts.
     *
     * @param target the target directory to validate is safe.
     */
    public static void validateSafeRelativeSymlink(Path target) {
        int numNames = 0;
        int numCdUps = 0;
        for (int i = 0; i < target.getNameCount(); i++) {
            if ("..".equals(target.getName(i).toString())) {
                numCdUps++;
            } else if (!".".equals(target.getName(i).toString())) {
                numNames++;
            }

            // need to check at each part to prevent data leakage outside of chroot
            if (numCdUps > numNames) {
                throw new InvalidPathException(target.toString(), "Symlink would exit chroot: " + target);
            }
        }
    }
}
