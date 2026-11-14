ANDROID BUILD NOTES
======================

These are inherited development notes for building and packaging the Qt GUI
for Android. Android is not an official Nito Core V4 release target. The steps
below have not been qualified with the current Qt 6 and Orchard toolchain;
use the [supported build profiles](nito/source-builds.md) for release binaries.


## Dependencies

Before proceeding with an Android build one needs to get the [Android SDK](https://developer.android.com/studio) and use the "SDK Manager" tool to download the NDK and one or more "Platform packages" (these are Android versions and have a corresponding API level).

The minimum supported Android NDK version is [r23](https://github.com/android/ndk/wiki/Changelog-r23).

In order to build `ANDROID_API_LEVEL` (API level corresponding to the Android version targeted, e.g. Android 9.0 Pie is 28 and its "Platform package" needs to be available) and `ANDROID_TOOLCHAIN_BIN` (path to toolchain binaries depending on the platform the build is being performed on) need to be set.

The API-level range in the original build instructions was 24 to 29. This is
historical build information, not current Nito V4 runtime validation.

If the build includes Qt, environment variables `ANDROID_SDK` and `ANDROID_NDK` need to be set as well but can otherwise be omitted.
This is an example command for a default build with no disabled dependencies:

    ANDROID_SDK=/home/user/Android/Sdk ANDROID_NDK=/home/user/Android/Sdk/ndk-bundle make HOST=aarch64-linux-android ANDROID_API_LEVEL=28 ANDROID_TOOLCHAIN_BIN=/home/user/Android/Sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin


## Building and packaging

After the depends are built configure with one of the resulting prefixes and run `make && make apk` in `src/qt`.
