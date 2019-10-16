/*     */ package org.apache.tomcat.jni;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ public class Status
/*     */ {
/*     */   public static final int APR_OS_START_ERROR = 20000;
/*     */   
/*     */ 
/*     */ 
/*     */ 
/*     */   public static final int APR_OS_ERRSPACE_SIZE = 50000;
/*     */   
/*     */ 
/*     */ 
/*     */   public static final int APR_OS_START_STATUS = 70000;
/*     */   
/*     */ 
/*     */ 
/*     */   public static final int APR_OS_START_USERERR = 120000;
/*     */   
/*     */ 
/*     */ 
/*     */   public static final int APR_OS_START_USEERR = 120000;
/*     */   
/*     */ 
/*     */ 
/*     */   public static final int APR_OS_START_CANONERR = 620000;
/*     */   
/*     */ 
/*     */   public static final int APR_OS_START_EAIERR = 670000;
/*     */   
/*     */ 
/*     */   public static final int APR_OS_START_SYSERR = 720000;
/*     */   
/*     */ 
/*     */   public static final int APR_SUCCESS = 0;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOSTAT = 20001;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOPOOL = 20002;
/*     */   
/*     */ 
/*     */   public static final int APR_EBADDATE = 20004;
/*     */   
/*     */ 
/*     */   public static final int APR_EINVALSOCK = 20005;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOPROC = 20006;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOTIME = 20007;
/*     */   
/*     */ 
/*     */   public static final int APR_ENODIR = 20008;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOLOCK = 20009;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOPOLL = 20010;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOSOCKET = 20011;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOTHREAD = 20012;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOTHDKEY = 20013;
/*     */   
/*     */ 
/*     */   public static final int APR_EGENERAL = 20014;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOSHMAVAIL = 20015;
/*     */   
/*     */ 
/*     */   public static final int APR_EBADIP = 20016;
/*     */   
/*     */ 
/*     */   public static final int APR_EBADMASK = 20017;
/*     */   
/*     */ 
/*     */   public static final int APR_EDSOOPEN = 20019;
/*     */   
/*     */ 
/*     */   public static final int APR_EABSOLUTE = 20020;
/*     */   
/*     */ 
/*     */   public static final int APR_ERELATIVE = 20021;
/*     */   
/*     */ 
/*     */   public static final int APR_EINCOMPLETE = 20022;
/*     */   
/*     */ 
/*     */   public static final int APR_EABOVEROOT = 20023;
/*     */   
/*     */ 
/*     */   public static final int APR_EBADPATH = 20024;
/*     */   
/*     */ 
/*     */   public static final int APR_EPATHWILD = 20025;
/*     */   
/*     */ 
/*     */   public static final int APR_ESYMNOTFOUND = 20026;
/*     */   
/*     */ 
/*     */   public static final int APR_EPROC_UNKNOWN = 20027;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOTENOUGHENTROPY = 20028;
/*     */   
/*     */ 
/*     */   public static final int APR_INCHILD = 70001;
/*     */   
/*     */ 
/*     */   public static final int APR_INPARENT = 70002;
/*     */   
/*     */ 
/*     */   public static final int APR_DETACH = 70003;
/*     */   
/*     */ 
/*     */   public static final int APR_NOTDETACH = 70004;
/*     */   
/*     */ 
/*     */   public static final int APR_CHILD_DONE = 70005;
/*     */   
/*     */ 
/*     */   public static final int APR_CHILD_NOTDONE = 70006;
/*     */   
/*     */ 
/*     */   public static final int APR_TIMEUP = 70007;
/*     */   
/*     */ 
/*     */   public static final int APR_INCOMPLETE = 70008;
/*     */   
/*     */ 
/*     */   public static final int APR_BADCH = 70012;
/*     */   
/*     */ 
/*     */   public static final int APR_BADARG = 70013;
/*     */   
/*     */ 
/*     */   public static final int APR_EOF = 70014;
/*     */   
/*     */ 
/*     */   public static final int APR_NOTFOUND = 70015;
/*     */   
/*     */ 
/*     */   public static final int APR_ANONYMOUS = 70019;
/*     */   
/*     */ 
/*     */   public static final int APR_FILEBASED = 70020;
/*     */   
/*     */ 
/*     */   public static final int APR_KEYBASED = 70021;
/*     */   
/*     */ 
/*     */   public static final int APR_EINIT = 70022;
/*     */   
/*     */ 
/*     */   public static final int APR_ENOTIMPL = 70023;
/*     */   
/*     */ 
/*     */   public static final int APR_EMISMATCH = 70024;
/*     */   
/*     */ 
/*     */   public static final int APR_EBUSY = 70025;
/*     */   
/*     */ 
/*     */   public static final int TIMEUP = 120001;
/*     */   
/*     */ 
/*     */   public static final int EAGAIN = 120002;
/*     */   
/*     */ 
/*     */   public static final int EINTR = 120003;
/*     */   
/*     */ 
/*     */   public static final int EINPROGRESS = 120004;
/*     */   
/*     */ 
/*     */   public static final int ETIMEDOUT = 120005;
/*     */   
/*     */ 
/*     */ 
/*     */   private static native boolean is(int paramInt1, int paramInt2);
/*     */   
/*     */ 
/*     */ 
/* 197 */   public static final boolean APR_STATUS_IS_ENOSTAT(int s) { return is(s, 1); }
/* 198 */   public static final boolean APR_STATUS_IS_ENOPOOL(int s) { return is(s, 2); }
/*     */   
/* 200 */   public static final boolean APR_STATUS_IS_EBADDATE(int s) { return is(s, 4); }
/* 201 */   public static final boolean APR_STATUS_IS_EINVALSOCK(int s) { return is(s, 5); }
/* 202 */   public static final boolean APR_STATUS_IS_ENOPROC(int s) { return is(s, 6); }
/* 203 */   public static final boolean APR_STATUS_IS_ENOTIME(int s) { return is(s, 7); }
/* 204 */   public static final boolean APR_STATUS_IS_ENODIR(int s) { return is(s, 8); }
/* 205 */   public static final boolean APR_STATUS_IS_ENOLOCK(int s) { return is(s, 9); }
/* 206 */   public static final boolean APR_STATUS_IS_ENOPOLL(int s) { return is(s, 10); }
/* 207 */   public static final boolean APR_STATUS_IS_ENOSOCKET(int s) { return is(s, 11); }
/* 208 */   public static final boolean APR_STATUS_IS_ENOTHREAD(int s) { return is(s, 12); }
/* 209 */   public static final boolean APR_STATUS_IS_ENOTHDKEY(int s) { return is(s, 13); }
/* 210 */   public static final boolean APR_STATUS_IS_EGENERAL(int s) { return is(s, 14); }
/* 211 */   public static final boolean APR_STATUS_IS_ENOSHMAVAIL(int s) { return is(s, 15); }
/* 212 */   public static final boolean APR_STATUS_IS_EBADIP(int s) { return is(s, 16); }
/* 213 */   public static final boolean APR_STATUS_IS_EBADMASK(int s) { return is(s, 17); }
/*     */   
/* 215 */   public static final boolean APR_STATUS_IS_EDSOPEN(int s) { return is(s, 19); }
/* 216 */   public static final boolean APR_STATUS_IS_EABSOLUTE(int s) { return is(s, 20); }
/* 217 */   public static final boolean APR_STATUS_IS_ERELATIVE(int s) { return is(s, 21); }
/* 218 */   public static final boolean APR_STATUS_IS_EINCOMPLETE(int s) { return is(s, 22); }
/* 219 */   public static final boolean APR_STATUS_IS_EABOVEROOT(int s) { return is(s, 23); }
/* 220 */   public static final boolean APR_STATUS_IS_EBADPATH(int s) { return is(s, 24); }
/* 221 */   public static final boolean APR_STATUS_IS_EPATHWILD(int s) { return is(s, 25); }
/* 222 */   public static final boolean APR_STATUS_IS_ESYMNOTFOUND(int s) { return is(s, 26); }
/* 223 */   public static final boolean APR_STATUS_IS_EPROC_UNKNOWN(int s) { return is(s, 27); }
/* 224 */   public static final boolean APR_STATUS_IS_ENOTENOUGHENTROPY(int s) { return is(s, 28); }
/*     */   
/*     */ 
/*     */ 
/*     */ 
/* 229 */   public static final boolean APR_STATUS_IS_INCHILD(int s) { return is(s, 51); }
/* 230 */   public static final boolean APR_STATUS_IS_INPARENT(int s) { return is(s, 52); }
/* 231 */   public static final boolean APR_STATUS_IS_DETACH(int s) { return is(s, 53); }
/* 232 */   public static final boolean APR_STATUS_IS_NOTDETACH(int s) { return is(s, 54); }
/* 233 */   public static final boolean APR_STATUS_IS_CHILD_DONE(int s) { return is(s, 55); }
/* 234 */   public static final boolean APR_STATUS_IS_CHILD_NOTDONE(int s) { return is(s, 56); }
/* 235 */   public static final boolean APR_STATUS_IS_TIMEUP(int s) { return is(s, 57); }
/* 236 */   public static final boolean APR_STATUS_IS_INCOMPLETE(int s) { return is(s, 58); }
/*     */   
/*     */ 
/*     */ 
/* 240 */   public static final boolean APR_STATUS_IS_BADCH(int s) { return is(s, 62); }
/* 241 */   public static final boolean APR_STATUS_IS_BADARG(int s) { return is(s, 63); }
/* 242 */   public static final boolean APR_STATUS_IS_EOF(int s) { return is(s, 64); }
/* 243 */   public static final boolean APR_STATUS_IS_NOTFOUND(int s) { return is(s, 65); }
/*     */   
/*     */ 
/*     */ 
/* 247 */   public static final boolean APR_STATUS_IS_ANONYMOUS(int s) { return is(s, 69); }
/* 248 */   public static final boolean APR_STATUS_IS_FILEBASED(int s) { return is(s, 70); }
/* 249 */   public static final boolean APR_STATUS_IS_KEYBASED(int s) { return is(s, 71); }
/* 250 */   public static final boolean APR_STATUS_IS_EINIT(int s) { return is(s, 72); }
/* 251 */   public static final boolean APR_STATUS_IS_ENOTIMPL(int s) { return is(s, 73); }
/* 252 */   public static final boolean APR_STATUS_IS_EMISMATCH(int s) { return is(s, 74); }
/* 253 */   public static final boolean APR_STATUS_IS_EBUSY(int s) { return is(s, 75); }
/*     */   
/*     */ 
/* 256 */   public static final boolean APR_STATUS_IS_EAGAIN(int s) { return is(s, 90); }
/* 257 */   public static final boolean APR_STATUS_IS_ETIMEDOUT(int s) { return is(s, 91); }
/* 258 */   public static final boolean APR_STATUS_IS_ECONNABORTED(int s) { return is(s, 92); }
/* 259 */   public static final boolean APR_STATUS_IS_ECONNRESET(int s) { return is(s, 93); }
/* 260 */   public static final boolean APR_STATUS_IS_EINPROGRESS(int s) { return is(s, 94); }
/* 261 */   public static final boolean APR_STATUS_IS_EINTR(int s) { return is(s, 95); }
/* 262 */   public static final boolean APR_STATUS_IS_ENOTSOCK(int s) { return is(s, 96); }
/* 263 */   public static final boolean APR_STATUS_IS_EINVAL(int s) { return is(s, 97); }
/*     */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Status.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */