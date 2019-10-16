package org.apache.tomcat.jni;

public abstract interface BIOCallback
{
  public abstract int write(byte[] paramArrayOfByte);
  
  public abstract int read(byte[] paramArrayOfByte);
  
  public abstract int puts(String paramString);
  
  public abstract String gets(int paramInt);
}


/* Location:              C:\Users\lgoldstein\.m2\repository\tomcat\tomcat-apr\5.5.23\tomcat-apr-5.5.23.jar!\org\apache\tomcat\jni\BIOCallback.class
 * Java compiler version: 2 (46.0)
 * JD-Core Version:       0.7.1
 */