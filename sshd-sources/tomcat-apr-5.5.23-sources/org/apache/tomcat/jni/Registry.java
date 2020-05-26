package org.apache.tomcat.jni;

public class Registry
{
  public static final int HKEY_CLASSES_ROOT = 1;
  public static final int HKEY_CURRENT_CONFIG = 2;
  public static final int HKEY_CURRENT_USER = 3;
  public static final int HKEY_LOCAL_MACHINE = 4;
  public static final int HKEY_USERS = 5;
  public static final int KEY_ALL_ACCESS = 1;
  public static final int KEY_CREATE_LINK = 2;
  public static final int KEY_CREATE_SUB_KEY = 4;
  public static final int KEY_ENUMERATE_SUB_KEYS = 8;
  public static final int KEY_EXECUTE = 16;
  public static final int KEY_NOTIFY = 32;
  public static final int KEY_QUERY_VALUE = 64;
  public static final int KEY_READ = 128;
  public static final int KEY_SET_VALUE = 256;
  public static final int KEY_WOW64_64KEY = 512;
  public static final int KEY_WOW64_32KEY = 1024;
  public static final int KEY_WRITE = 2048;
  public static final int REG_BINARY = 1;
  public static final int REG_DWORD = 2;
  public static final int REG_EXPAND_SZ = 3;
  public static final int REG_MULTI_SZ = 4;
  public static final int REG_QWORD = 5;
  public static final int REG_SZ = 6;
  
  public static native long create(int paramInt1, String paramString, int paramInt2, long paramLong)
    throws Error;
  
  public static native long open(int paramInt1, String paramString, int paramInt2, long paramLong)
    throws Error;
  
  public static native int close(long paramLong);
  
  public static native int getType(long paramLong, String paramString);
  
  public static native int getValueI(long paramLong, String paramString)
    throws Error;
  
  public static native long getValueJ(long paramLong, String paramString)
    throws Error;
  
  public static native int getSize(long paramLong, String paramString);
  
  public static native String getValueS(long paramLong, String paramString)
    throws Error;
  
  public static native String[] getValueA(long paramLong, String paramString)
    throws Error;
  
  public static native byte[] getValueB(long paramLong, String paramString)
    throws Error;
  
  public static native int setValueI(long paramLong, String paramString, int paramInt);
  
  public static native int setValueJ(long paramLong, String paramString, int paramInt);
  
  public static native int setValueS(long paramLong, String paramString1, String paramString2);
  
  public static native int setValueE(long paramLong, String paramString1, String paramString2);
  
  public static native int setValueA(long paramLong, String paramString, String[] paramArrayOfString);
  
  public static native int setValueB(long paramLong, String paramString, byte[] paramArrayOfByte);
  
  public static native String[] enumKeys(long paramLong)
    throws Error;
  
  public static native String[] enumValues(long paramLong)
    throws Error;
  
  public static native int deleteValue(long paramLong, String paramString);
  
  public static native int deleteKey(int paramInt, String paramString, boolean paramBoolean);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\Registry.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */