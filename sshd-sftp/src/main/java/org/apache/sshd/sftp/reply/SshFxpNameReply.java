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
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.server.SshFile;

/**
 * Data container for 'SSH_FXP_NAME' reply.
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class SshFxpNameReply implements Reply {
	/**
	 * Contains informations of requested files.
	 */
	public static class ReplyFile {

		private final String filename;
		private final String longname;
		private final Integer x;
		private final FileAttributes attrs;

		/**
		 * Creates ReplyFile instance.
		 * 
		 * @param filename The file name.
		 * @param longname The virtual absolute file path.
		 * @param x        Do not know.
		 */
		public ReplyFile(final String filename, final String longname, final int x) {
			this.filename = filename;
			this.longname = longname;
			this.x = x;
			attrs = null;
		}

		/**
		 * Creates ReplyFile instance.
		 * 
		 * @param filename The file name.
		 * @param longname The virtual absolute file path.
		 * @param attrs    The file attributes.
		 */
		public ReplyFile(final String filename, final String longname, final FileAttributes attrs) {
			this.filename = filename;
			this.longname = longname;
			this.attrs = attrs;
			x = null;
		}

		/**
		 * {@inheritDoc}
		 */
		public String toString() {
			return "filename=" + filename + ", longname=" + longname;
		}

		/**
		 * Returns x. Do not know the meaning.
		 * 
		 * @return x value.
		 */
		public int getX() {
			return x;
		}

		/**
		 * Returns the file attributes.
		 * 
		 * @return The file attributes.
		 */
		public FileAttributes getAttrs() {
			return attrs;
		}
	}

	private List<ReplyFile> fileList = new ArrayList<ReplyFile>();
	private final int id;
	private int count = 0;
	private Collection<SshFile> sshFiles = new ArrayList<SshFile>();
	private final boolean isSendPath;

	/**
	 * Creates a SshFxpHandleReply instance.
	 * 
	 * @param id         The reply id.
	 * @param isSendPath If true, it's a send path reply.
	 */
	public SshFxpNameReply(final int id, final boolean isSendPath) {
		this.id = id;
		this.isSendPath = isSendPath;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getReplyCodeName() {
		return "SSH_FXP_NAME";
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		StringBuffer fs = new StringBuffer();
		fs.append(getReplyCodeName());
		fs.append(": id=");
		fs.append(id);
		fs.append(", count=");
		fs.append(count);
		fs.append(",");
		fs.append("\n");
		for (ReplyFile f : fileList) {
			fs.append(f.toString());
			fs.append(";\n");
	    }

		return fs.toString();
	}

	/**
	 * Add a file to the reply.
	 * 
	 * @param sshFile  The ssh file.
	 * @param filename The file name.
	 * @param longname The long file message.
	 * @param x        Don't know!
	 */
	public void addFile(final SshFile sshFile, final String filename, final String longname, final int x) {
		ReplyFile file = new ReplyFile(filename, longname, x);
		fileList.add(file);
		sshFiles.add(sshFile);
		count++;
	}

	/**
	 * Add a file to the reply.
	 * 
	 * @param sshFile  The ssh file.
	 * @param filename The file name.
	 * @param longname The long file message.
	 * @param attrs    The file attributes.
	 */
	public void addFile(final SshFile sshFile, final String filename, final String longname,
			final FileAttributes attrs) {
		ReplyFile file = new ReplyFile(filename, longname, attrs);
		fileList.add(file);
		sshFiles.add(sshFile);
		count++;
	}

	/**
	 * Returns the id.
	 * 
	 * @return The id.
	 */
	public int getId() {
		return id;
	}

	/**
	 * Returns the files.
	 * 
	 * @return the files.
	 */
	public Iterator<SshFile> getFiles() {
		return sshFiles.iterator();
	}

	/**
	 * Returns the send path reply flag.
	 * 
	 * @return True, it's a send path reply.
	 */
	public boolean isSendPath() {
		return isSendPath;
	}
}
