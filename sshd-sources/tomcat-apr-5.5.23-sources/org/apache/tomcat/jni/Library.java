/*     */ package org.apache.tomcat.jni;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ public final class Library
/*     */ {
/*  29 */   private static String[] NAMES = { "tcnative-1", "libtcnative-1" };
/*     */   
/*     */ 
/*     */ 
/*  33 */   private static Library _instance = null;
/*     */   
/*     */   private Library()
/*     */   {
/*  37 */     boolean loaded = false;
/*  38 */     String err = "";
/*  39 */     for (int i = 0; i < NAMES.length; i++) {
/*     */       try {
/*  41 */         System.loadLibrary(NAMES[i]);
/*  42 */         loaded = true;
/*     */       }
/*     */       catch (Throwable e) {
/*  45 */         if (i > 0)
/*  46 */           err = err + ", ";
/*  47 */         err = err + e.getMessage();
/*     */       }
/*  49 */       if (loaded)
/*     */         break;
/*     */     }
/*  52 */     if (!loaded) {
/*  53 */       err = err + "(";
/*  54 */       err = err + System.getProperty("java.library.path");
/*  55 */       err = err + ")";
/*  56 */       throw new UnsatisfiedLinkError(err);
/*     */     }
/*     */   }
/*     */   
/*     */   private Library(String libraryName)
/*     */   {
/*  62 */     System.loadLibrary(libraryName);
/*     */   }
/*     */   
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*  81 */   public static int TCN_MAJOR_VERSION = 0;
/*     */   
/*  83 */   public static int TCN_MINOR_VERSION = 0;
/*     */   
/*  85 */   public static int TCN_PATCH_VERSION = 0;
/*     */   
/*  87 */   public static int TCN_IS_DEV_VERSION = 0;
/*     */   
/*  89 */   public static int APR_MAJOR_VERSION = 0;
/*     */   
/*  91 */   public static int APR_MINOR_VERSION = 0;
/*     */   
/*  93 */   public static int APR_PATCH_VERSION = 0;
/*     */   
/*  95 */   public static int APR_IS_DEV_VERSION = 0;
/*     */   
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/* 103 */   public static boolean APR_HAVE_IPV6 = false;
/* 104 */   public static boolean APR_HAS_SHARED_MEMORY = false;
/* 105 */   public static boolean APR_HAS_THREADS = false;
/* 106 */   public static boolean APR_HAS_SENDFILE = false;
/* 107 */   public static boolean APR_HAS_MMAP = false;
/* 108 */   public static boolean APR_HAS_FORK = false;
/* 109 */   public static boolean APR_HAS_RANDOM = false;
/* 110 */   public static boolean APR_HAS_OTHER_CHILD = false;
/* 111 */   public static boolean APR_HAS_DSO = false;
/* 112 */   public static boolean APR_HAS_SO_ACCEPTFILTER = false;
/* 113 */   public static boolean APR_HAS_UNICODE_FS = false;
/* 114 */   public static boolean APR_HAS_PROC_INVOKED = false;
/* 115 */   public static boolean APR_HAS_USER = false;
/* 116 */   public static boolean APR_HAS_LARGE_FILES = false;
/* 117 */   public static boolean APR_HAS_XTHREAD_FILES = false;
/* 118 */   public static boolean APR_HAS_OS_UUID = false;
/*     */   
/* 120 */   public static boolean APR_IS_BIGENDIAN = false;
/*     */   
/*     */ 
/*     */ 
/* 124 */   public static boolean APR_FILES_AS_SOCKETS = false;
/*     */   
/*     */ 
/* 127 */   public static boolean APR_CHARSET_EBCDIC = false;
/*     */   
/*     */ 
/* 130 */   public static boolean APR_TCP_NODELAY_INHERITED = false;
/*     */   
/*     */ 
/* 133 */   public static boolean APR_O_NONBLOCK_INHERITED = false;
/*     */   public static int APR_SIZEOF_VOIDP;
/*     */   public static int APR_PATH_MAX;
/*     */   public static int APRMAXHOSTLEN;
/*     */   
/*     */   private static native boolean initialize();
/*     */   
/*     */   public static native void terminate();
/*     */   
/*     */   private static native boolean has(int paramInt);
/*     */   
/*     */   private static native int version(int paramInt);
/*     */   
/*     */   private static native int size(int paramInt);
/*     */   
/*     */   public static native String versionString();
/*     */   
/*     */   public static native String aprVersionString();
/*     */   
/*     */   public static native long globalPool();
/*     */   
/*     */   public static boolean initialize(String libraryName) throws Exception {
/* 155 */     if (_instance == null) {
/* 156 */       if (libraryName == null) {
/* 157 */         _instance = new Library();
/*     */       } else
/* 159 */         _instance = new Library(libraryName);
/* 160 */       TCN_MAJOR_VERSION = version(1);
/* 161 */       TCN_MINOR_VERSION = version(2);
/* 162 */       TCN_PATCH_VERSION = version(3);
/* 163 */       TCN_IS_DEV_VERSION = version(4);
/* 164 */       APR_MAJOR_VERSION = version(17);
/* 165 */       APR_MINOR_VERSION = version(18);
/* 166 */       APR_PATCH_VERSION = version(19);
/* 167 */       APR_IS_DEV_VERSION = version(20);
/*     */       
/* 169 */       APR_SIZEOF_VOIDP = size(1);
/* 170 */       APR_PATH_MAX = size(2);
/* 171 */       APRMAXHOSTLEN = size(3);
/* 172 */       APR_MAX_IOVEC_SIZE = size(4);
/* 173 */       APR_MAX_SECS_TO_LINGER = size(5);
/* 174 */       APR_MMAP_THRESHOLD = size(6);
/* 175 */       APR_MMAP_LIMIT = size(7);
/*     */       
/* 177 */       APR_HAVE_IPV6 = has(0);
/* 178 */       APR_HAS_SHARED_MEMORY = has(1);
/* 179 */       APR_HAS_THREADS = has(2);
/* 180 */       APR_HAS_SENDFILE = has(3);
/* 181 */       APR_HAS_MMAP = has(4);
/* 182 */       APR_HAS_FORK = has(5);
/* 183 */       APR_HAS_RANDOM = has(6);
/* 184 */       APR_HAS_OTHER_CHILD = has(7);
/* 185 */       APR_HAS_DSO = has(8);
/* 186 */       APR_HAS_SO_ACCEPTFILTER = has(9);
/* 187 */       APR_HAS_UNICODE_FS = has(10);
/* 188 */       APR_HAS_PROC_INVOKED = has(11);
/* 189 */       APR_HAS_USER = has(12);
/* 190 */       APR_HAS_LARGE_FILES = has(13);
/* 191 */       APR_HAS_XTHREAD_FILES = has(14);
/* 192 */       APR_HAS_OS_UUID = has(15);
/* 193 */       APR_IS_BIGENDIAN = has(16);
/* 194 */       APR_FILES_AS_SOCKETS = has(17);
/* 195 */       APR_CHARSET_EBCDIC = has(18);
/* 196 */       APR_TCP_NODELAY_INHERITED = has(19);
/* 197 */       APR_O_NONBLOCK_INHERITED = has(20);
/* 198 */       if (APR_MAJOR_VERSION < 1) {
/* 199 */         throw new UnsatisfiedLinkError("Unsupported APR Version (" + aprVersionString() + ")");
/*     */       }
/*     */       
/* 202 */       if (!APR_HAS_THREADS) {
/* 203 */         throw new UnsatisfiedLinkError("Missing APR_HAS_THREADS");
/*     */       }
/*     */     }
/* 206 */     return initialize();
/*     */   }
/*     */   
/*     */   public static int APR_MAX_IOVEC_SIZE;
/*     */   public static int APR_MAX_SECS_TO_LINGER;
/*     */   public static int APR_MMAP_THRESHOLD;
/*     */   public static int APR_MMAP_LIMIT;
/*     */ }


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Library.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */