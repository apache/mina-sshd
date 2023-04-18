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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Utility functions for rooted file utils
 */
public final class RootedFileSystemUtils {

    private RootedFileSystemUtils() {
        // do not construct
    }

    static Path chrootDirectory(Path root, Path toResolve) {
        // initialize a list for the new file name parts
        List<String> newNames = new ArrayList<>(toResolve.getNameCount());

        int numCdUps = 0;
        int numDirParts = 0;
        for (int i = 0; i < toResolve.getNameCount(); i++) {
            String name = toResolve.getName(i).toString();
            if ("..".equals(name)) {
                // If we have more cdups than dir parts, so we ignore the ".." to avoid jail escapes
                if (numDirParts > numCdUps) {
                    ++numCdUps;
                    newNames.add(name);
                }
            } else {
                // if the current directory is a part of the name, don't increment number of dir parts, as it doesn't
                // add to the number of ".."s that can be present before the root
                if (!".".equals(name)) {
                    ++numDirParts;
                }
                newNames.add(name);
            }
        }
        return buildPath(root, newNames);
    }

    private static Path buildPath(Path root, List<String> namesList) {
        if (namesList.isEmpty()) {
            return root;
        }

        String[] names = new String[namesList.size() - 1];

        Iterator<String> it = namesList.iterator();
        String rootName = it.next();
        for (int i = 0; it.hasNext(); i++) {
            names[i] = it.next();
        }
        Path cleanedPathToResolve = root.getFileSystem().getPath(rootName, names);
        return root.resolve(cleanedPathToResolve);
    }

    static void validateSafeRelativeSymlink(Path target) {
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
