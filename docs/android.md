# Android support

The SSHD team has not checked the compatibility and usability of the libraries for the Android O/S. Furthermore, at present it is not a stated goal of this project to actively support it, mainly because of the dire lack of available R&D resources and the relatively time consuming task of developing and testing code for Android. That being said, several "hooks" have been implemented aimed at facilitating the usage of these libraries on Android, though (as stated) no serious effort was made to thoroughly test them. The implemented support relies on feedback from users who have attempted this feat, the problems they discovered and how they tried (or failed) to overcome them.

## Specific issues

### O/S detection

[OsUtils](../sshd-common/src/main/java/org/apache/sshd/common/util/OsUtils.java) has been enhanced to both automatically attempt to detect if currently runing in Android or being told so explicitly by the user - see `isAndroid/setAndroid` method(s).

### Accessing the current working directory

Instead of accessing the `user.dir` system property directly (which is missing in Android) [OsUtils](../sshd-common/src/main/java/org/apache/sshd/common/util/OsUtils.java) has been enhanced to provide a `getCurrentWorkingDirectory` method - which by default still uses the `user.dir` system property. However, the user can use `setCurrentWorkingDirectoryResolver` to reigster a callback that will return some user-controlled location instead. This is most important for [ScpFileOpener](../sshd-scp/src/main/java/org/apache/sshd/scp/common/ScpFileOpener.java) `getMatchingFilesToSend` default implementation that uses the CWD as its base path if none provided by the caller.

### Detecting the user's home directory

Instead of accessing the `user.home` system property directly (which is missing in Android) [PathUtils](../sshd-common/src/main/java/org/apache/sshd/common/util/io/PathUtils.java) now provides a `getUserHomeFolder` which by default still consults the `user.home` system property, unless the user has invoked `setUserHomeFolderResolver` to provide a replacement for it.

Another aspect of this issue is the assignment of user "home" folder by a *server* that is running on Android. The [NativeFileSystemFactory](../sshd-common/src/main/java/org/apache/sshd/common/file/nativefs/NativeFileSystemFactory.java) auto-detects this folder for standard O/S, but for Android one needs to call its `setUsersHomeDir` method **explicitly** - or extend it and override `getUserHomeDir` method.

 It can also be helpful for an [SftpSubsystem](../sshd-sftp/src/main/java/org/apache/sshd/sftp/server/SftpSubsystem.java) or a [ShellFactory](../sshd-core/src/main/java/org/apache/sshd/server/shell/ShellFactory.java) implementation when they provide the concept of a user's "HOME" location.

A similar mechanism has been implemented for [`PGPUtils#getDefaultPgpFolderPath`](../sshd-openpgp/src/main/java/org/apache/sshd/openpgp/PGPUtils.java), though it depends on the `PathUtils#getUserHomeFolder` mechanism, so if one manages `getUserHomeFolder` correctly, `PGPUtils#getDefaultPgpFolderPath` would align with it as well without need for further intervention.
 
### O/S dependenent code flow

There are a few locations where special consideration was made if the code detects that it is running on Android - these choices were made based on our current understanding of Android and are **independent** of the device's O/S API level.  E.g. the [KeyUtils](../sshd-common/src/main/java/org/apache/sshd/common/config/keys/KeyUtils.java) `validateStrictKeyFilePermissions` method returns an always valid result for Android. **Important notice:** if API-level dependent flows are required, then much deeper change may be required.

### [Security provider(s)](./security-providers.md)

The SSHD code uses *Bouncycastle* if it detects it - however, on Android this can cause some issues - especially if the user's code also contains the BC libraries. It is not clear how to use it - especially since some articles suggest that BC is bundled into Android or has been so and now it is deprecated.  Several [Stackoverflow](https://stackoverflow.com/) posts suggest that an **explicit** management is required - e.g.:

```java
import java.security.Security;

Security.removeProvider("BC" or "Bouncycastle");
Security.addProvider(new BouncycastleProvider());
```

The *sshd-contrib* module contains a [AndroidOpenSSLSecurityProviderRegistrar](../sshd-contrib/src/main/java/org/apache/sshd/contrib/common/util/security/androidopenssl/AndroidOpenSSLSecurityProviderRegistrar.java) class that can supposedly be used via the [`SecurityUtils.registerSecurityProvider()`](../sshd-common/src/main/java/org/apache/sshd/common/util/security/SecurityUtils.java) call. **Note:** we do not know for sure if this works for all/part of the needed security requirements since the code was donated without any in-depth explanation other than that "is works".

### Using [MINA](../sshd-mina) or [Netty](../sshd-netty) I/O factories

These factories have not been tested on Android and it is not clear if they work on it.

## Example code

The following is a simple/naive/simplistic code sample demonstrating the required initializations for an Android application using the SSHD code. Users are of course invited to make the necessary adjustments for their specific needs.

```java
import android.app.Application;

public class MyApplication extends Application {
    public MyApplication() {
        OsUtils.setAndroid(Boolean.TRUE);    // if don't trust the automatic detection
        System.setProperty("user.name", "....whatever...");   // just in case
        OsUtils.setCurrentUser("....whatever...");
    }
   
    @Override
    public void onCreate() {
        super.onCreate();

        // This is just an example - you are welcome to use whatever location you want 
        File filesDir = getFilesDir();
        Path filesPath = filesDir.toPath();
        System.setProperty("user.home", filesPath.toString());   // just in case
        PathUtils.setUserHomeFolderResolver(() -> filesPath);
        System.setProperty("user.dir", filesPath.toString());   // just in case
        OsUtils.setCurrentWorkingDirectoryResolver(() -> filesPath);
        
        ...setup security provider(s)...
    }
}
```

**Note:** these are the most *basic* settings - various extra adjustments might be required and they must be dealt with on a case-by-case manner. We do believe though that the code is flexible enough to provide the necessary solutions. As previously stated, even though we do not define Android as a goal, we would appreciate feedback on problems and solutions our users have encountered when running on Android (or iOs for that matter), and what suggestions they have for code changes that would facilitate this task - see [SSHD development mailing list](mailto:dev@mina.apache.org) or open an issue on this project - or better yet, a PR.

## Further possible features

Several Android related features come to mind as being useful, but as stated, due to severe lack of R&D resources (and not much demand from the community) we cannot devote the necessary effort to implement them. They are listed here in case they spark interest and someone undertakes their implementation (and hopefully contributes back via a PR).

### [Uri](https://developer.android.com/reference/android/net/Uri?hl=en)-based [FileSystemProvider](https://developer.android.com/reference/java/nio/file/spi/FileSystemProvider) and [FileSystem](https://developer.android.com/reference/java/nio/file/FileSystem)

The idea is to be able to wrap a [Uri](https://developer.android.com/reference/android/net/Uri?hl=en) that represents a files tree (e.g., obtained via [ACTION_OPEN_DOCUMENT_TREE](https://developer.android.com/reference/android/content/Intent#ACTION_OPEN_DOCUMENT_TREE)) into a [FileSystemProvider](https://developer.android.com/reference/java/nio/file/spi/FileSystemProvider) and [FileSystem](https://developer.android.com/reference/java/nio/file/FileSystem) so that it can be used to provide [Path](https://developer.android.com/reference/java/nio/file/Path.html)-like objects to SCP/SFTP client/server. The existing [DocumentFile](https://developer.android.com/reference/androidx/documentfile/provider/DocumentFile) support object can be very helpful for this purpose.

In this context, it would be helpful to have an Android specific library that provides API wrappers that use *Uri*-s instead of *Path*-s - e.g.:

* Loading/Storing keys
* Copy files/directories through SCP/SFTP
* Accessing configuration files
 
**Important note**: it may become necessary to enhance the existing core code to support these features (which is fine) - however, the limitation is that we cannot include references to Android-specific classes in our core code. Any such references must be contained entirely into **separate** dedicated library(ies) that may use "hooks" placed in the core code. Furthermore, these hooks must reference only Java 8 classes that are supported by Android (regardless of the API level).

## Using [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences?hl=en) for global [configuration](https://github.com/apache/mina-sshd/blob/master/docs/internals.md#properties-and-inheritance-model)

The SSHD code contains a robust and flexible mechanism for [configuring](https://github.com/apache/mina-sshd/blob/master/docs/internals.md#properties-and-inheritance-model) various properties used internally to control performance, memory and resources allocation, behavior, etc.. This mechanism relies heavily on Java properties which cannot be controlled when an Android application is launched. Instead, one could use the [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences?hl=en) mechanism to store the user's choices, as well as editing and then using these properties to configure the SSHD code when application starts.

### Demo application(s) as part of the SSHD code

It would be very helpful to have several Android demo applications as part of the delivered SSHD code. These applications can demonstrate to users how to integrate SSHD into Android applications as well as serve as a very useful platform for debugging existing code and implementating future features. E.g.,

* [WinSCP](https://winscp.net/eng/index.php)-like application to test SFTP/SCP code.
* [Putty](https://www.putty.org/)-like application to test remote shell.
* Basic server application - very interesting use-case in conjunction with Android - turning one's phone/tablet into a public SSH server via becoming a WiFi hotspot.