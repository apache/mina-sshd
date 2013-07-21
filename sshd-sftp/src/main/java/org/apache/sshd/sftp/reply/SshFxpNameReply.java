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
package org.apache.sshd.sftp.reply;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.sftp.subsystem.SftpConstants;

/**
 * Data container for 'SSH_FXP_NAME' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpNameReply extends BaseReply {
	/**
	 * Contains informations of requested files.
	 */
	public static class ReplyFile {

        private final SshFile file;
		private final String fileName;
		private final String longName;
		private final FileAttributes attrs;

		/**
		 * Creates ReplyFile instance.
		 * 
		 * @param fileName The file name.
		 * @param longName The virtual absolute file path.
		 * @param attrs    File attributes.
		 */
		public ReplyFile(final SshFile file, final String fileName, final String longName, final FileAttributes attrs) {
            this.file = file;
			this.fileName = fileName;
			this.longName = longName;
			this.attrs = attrs;
		}

        public SshFile getFile() {
            return file;
        }

        public String getFileName() {
            return fileName;
        }

        public String getLongName() {
            return longName;
        }

        /**
         * Returns the file attributes.
         *
         * @return The file attributes.
         */
        public FileAttributes getAttrs() {
            return attrs;
        }

        public String toString() {
            return "fileName=" + fileName + ", longName=" + longName;
        }

    }

	private List<ReplyFile> files = new ArrayList<ReplyFile>();
    private boolean eol;

    /**
	 * Creates a SshFxpHandleReply instance.
	 * 
	 * @param id         The reply id.
	 */
	public SshFxpNameReply(final int id) {
		super(id);
    }

	/**
	 * {@inheritDoc}
	 */
    public SftpConstants.Type getMessage() {
        return SftpConstants.Type.SSH_FXP_NAME;
    }

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		StringBuffer fs = new StringBuffer();
		fs.append(getName());
        fs.append("[");
		fs.append("\n");
		for (ReplyFile f : files) {
            fs.append("    ");
			fs.append(f.toString());
			fs.append(",\n");
	    }
        fs.append("]");

		return fs.toString();
	}

	/**
	 * Add a file to the reply.
	 * 
	 * @param sshFile  The ssh file.
	 * @param filename The file name.
	 * @param longname The long file message.
	 * @param attrs    The file attributes.
	 */
	public void addFile(final SshFile sshFile, final String filename, final String longname, final FileAttributes attrs) {
		files.add(new ReplyFile(sshFile, filename, longname, attrs));
	}

	/**
	 * Returns the files.
	 * 
	 * @return the files.
	 */
	public Collection<ReplyFile> getFiles() {
		return files;
	}

    public boolean isEol() {
        return eol;
    }

    public void setEol(boolean eol) {
        this.eol = eol;
    }
}
