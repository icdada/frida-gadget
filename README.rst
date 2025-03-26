frida-gadget
============

|Codacy-Grade| |Docker| |LICENCE|


| ``frida-gadget`` is a tool for patching Android applications to integrate the `Frida Gadget <https://frida.re/docs/gadget/>`_.
| This tool automates the process of downloading the Frida gadget library and injecting the ``loadLibrary`` code into the main activity.


Installation
------------

|Py-Versions| |PyPI-Downloads|

.. code:: sh

    pip install frida-gadget --upgrade

Prerequirement
----------------

| You should install ``apktool`` and add it to your ``PATH`` environment variable.
|   

.. code:: sh

   # Install Apktool on macOS
   brew install apktool
    
   # Add Apktool to your PATH environment variable
   export PATH=$PATH:$HOME/.brew/bin 

| For other operating systems, such as ``Windows``, you can refer to the `Install Guide <https://ibotpeaches.github.io/Apktool/install/>`_.


Usage
------------

.. code:: sh

    $ frida-gadget --help
      Usage: cli.py [OPTIONS] APK_PATH

      Patch an APK with the Frida gadget library
    
      Options:
         --arch TEXT                Specify the target architecture of the device. (options: arm64, x86_64, arm, x86)
         --config TEXT              Specify the Frida configuration file.
         --js TEXT                  Specify the Frida gadget JavaScript file.
         --js-delay INTEGER         Specify seconds to wait before executing the JavaScript file.
         --force-manifest           Force modify AndroidManifest.xml even if it already has required permissions.
         --custom-gadget-name TEXT  Specify a custom name for the Frida gadget.
         --no-res                   Skip decoding resources.
         --main-activity TEXT       Specify the main activity if known.
         --sign                     Automatically sign the APK using uber-apk-signer.
         --skip-decompile           Skip the decompilation step.
         --skip-recompile           Skip the recompilation step.
         --use-aapt2                Use aapt2 instead of aapt for resource processing.
         --decompile-opts TEXT      Specify additional options for apktool decompile.
         --recompile-opts TEXT      Specify additional options for apktool recompile.
         --apktool-path TEXT        Specify the path or command to run apktool.
         --frida-version TEXT       Specify the Frida version to use.
         --version                  Show the version and exit.
         --help                     Show this message and exit.

How do I begin?
~~~~~~~~~~~~~~~~~~~~~~
| Simply provide the APK file with the target architecture.
|

.. code:: sh

    $ frida-gadget target.apk --sign
      [INFO] Auto-detected frida version: 16.1.3
      [INFO] APK: '[REDACTED]/demo-apk/target.apk'
      [INFO] Auto-detected architecture via ADB: arm64-v8a # Alternatively, specify the architecture with --arch arm64
      [INFO] Gadget Architecture(--arch): arm64(default)
      [DEBUG] Decompiling the target APK using apktool
      [DEBUG] Downloading the frida gadget library for arm64
      [DEBUG] Checking internet permission and extractNativeLibs settings
      [DEBUG] Adding 'android.permission.INTERNET' permission to AndroidManifest.xml
      [DEBUG] Searching for the main activity in the smali files
      [DEBUG] Found the main activity at '[REDACTED]/frida-gadget/tests/demo-apk/target/smali/com/google/mediap/apps/target/MainActivity.smali'
      [DEBUG] Locating the onCreate method and injecting the loadLibrary code
      [DEBUG] Recompiling the new APK using apktool
      ...
      [INFO] APK signing finished: ./target/dist/target-aligned-debugSigned.apk (72.78 MiB)

With Docker
~~~~~~~~~~~~~~~~~~
| You can also use this tool with Docker. Here's how to use it:
|
| 1. First, pull the Docker image:
|

.. code:: sh

    docker pull ksg97031/frida-gadget

| 2. Mount your local directory containing the APK file to the container:
|

.. code:: sh

    docker run -v $(pwd):/workspace/mount ksg97031/frida-gadget /workspace/mount/your-app.apk --arch arm64 --sign

| Note: Replace ``your-app.apk`` with your actual APK filename. The patched APK will be created in the same directory as your original APK.
|
| For example, if your APK is named ``example.apk``:
|

.. code:: sh

    docker run -v $(pwd):/workspace/mount ksg97031/frida-gadget /workspace/mount/example.apk --arch arm64 --sign
    # The patched APK will be located at ./example/dist/example.apk

Compatibility
----------------
Device Architecture
~~~~~~~~~~~~~~~~~~~~~~~
| The tool automatically detects the device architecture when an ADB device is connected. You can also manually specify the architecture using the ``--arch`` option.
|
| To determine your device's architecture, connect your device and run the following command:
|

.. code:: sh

    adb shell getprop ro.product.cpu.abi

| This command will output the architecture of your device, such as ``arm64-v8a``, ``armeabi-v7a``, ``x86``, ``x86_64`` or ``multi-arch``.

| Example of automatic detection:
|

.. code:: sh

    $ frida-gadget target.apk --sign
    [INFO] Auto-detected architecture via ADB: arm64-v8a

| Example of manual specification:
|

.. code:: sh

    $ frida-gadget target.apk --arch arm64 --sign
    [INFO] Gadget Architecture(--arch): arm64

Android Version Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~
| The following table shows the minimum Frida version required for different Android versions:
| (Note: This information may not be completely accurate)

.. list-table::
   :header-rows: 1

   * - Android Version
     - Minimum Frida Version
     - Notes
   * - Android 5.x ~ 7.x (Lollipop~Nougat)
     - Frida 14.2+
     - Support for older Android versions was improved in Frida 12.6. Frida 14.2 includes fixes for libc detection errors and restored Houdini (translator) support. Latest Frida (16.x) continues to support Android 5~7.
   * - Android 8.0 ~ 8.1 (Oreo)
     - Frida 12.6.6+
     - Java API issues like Java.choose were resolved in Frida 12.6.3+. Java integration issues on 32-bit ARM devices were fixed in Frida 12.6.6. Frida 14.x and newer versions work stably on Oreo.
   * - Android 9.0 (Pie)
     - Frida 12.7+
     - Frida was extensively tested on Pixel 3 (Android 9). Frida 12.x ~ 15.x versions work stably on AOSP-based Android 9. Latest Frida 16.x also supports Android 9. (For emulators, Google-provided Android 9 images for arm/arm64 are recommended.)
   * - Android 10 (Q)
     - Frida 14.2+
     - While there were no major changes specific to Android 10, Frida 14.2+ is recommended for overall stability. Frida 14.2 includes various compatibility improvements for both pre and post Android 10 versions. Latest Frida 15.x and 16.x versions work without issues on Android 10.
   * - Android 11 (R)
     - Frida 14.2+
     - Frida 14.2 includes modifications to address ART changes and ARM->x86 translation in Android 11. Frida 14.2 or higher is recommended for Android 11. Frida 15.x~16.x fully support Android 11. (May have separate issues on custom ROMs like Samsung.)
   * - Android 12 (S)
     - Frida 15.0+
     - Official support for Android 12 was first added in Frida 15.0. Initial 15.0 version had minor compatibility issues, but Frida 15.1.23 includes several stability improvements for Android 12. Frida 15.1.23 or higher (preferably 15.2 or latest 16.x) is recommended for Android 12 devices.
   * - Android 13 (T)
     - Frida 15.1.23+
     - Preliminary support for Android 13 was introduced in Frida 15.1.23, and support matured in Frida 16.x versions. Minimum Frida 15.1.23 is required for Android 13 devices, but using the latest Frida 16 version is recommended (includes fixes for Android 13's internal behavior changes).
   * - Android 14 (UpsideDownCake)
     - Frida 16.2.0+
     - Due to ART structure changes in Android 14, initial Frida 16.0~16.1 versions had issues with Java hooking, but Frida 16.2.0 improved hooking support for Android 14. Frida 16.2 or higher is recommended for Android 14 (Frida 16.2 added support for Android 14's new ART entrypoints).

How to Identify the Injection?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| You can observe the main activity to see the injected ``loadLibrary`` code.
| Additionally, the Frida gadget library will be present in your APK.

.. code:: sh

    $ unzip -l [REDACTED]/demo-apk/target/dist/target.apk | grep libfrida-gadget
      21133848  09-15-2021 02:28   lib/arm64-v8a/libfrida-gadget-16.1.3-android-arm64.so 

Tips
------------

Specifying a Different Main Activity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| If the main activity is not automatically detected, you can specify it manually using the ``--main-activity`` option:
|

.. code:: sh

    $ frida-gadget target.apk --main-activity com.example.MainActivity --no-res --sign

Creating Self-Contained SSL Bypass App with --js
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| 1. Download the `@akabe1/frida-multiple-unpinning <https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/>`_ script.
| 2. Inject the script into the target application using the ``--js`` flag.

.. code:: sh

    frida-gadget target.apk --js frida-multiple-unpinning.js --sign --no-res

| 3. Run the injected application on your device or emulator.
| 4. Observe the network traffic using a proxy tool such as `Burp Suite <https://portswigger.net/burp>`_ or `Caido <https://caido.io/>`_.
|
| Note: If the app crashes, try adding ``--js-delay 2`` to delay script execution:

.. code:: sh

    frida-gadget target.apk --js frida-multiple-unpinning.js --js-delay 2 --sign --no-res

| This gives the app time to initialize before applying hooks.
|
| You can also specify a custom Frida version using ``--frida-version``:

.. code:: sh

    frida-gadget target.apk --js frida-multiple-unpinning.js --frida-version 16.1.3 --sign --no-res

| This is useful when you need to use a specific Frida version for compatibility reasons.

Using a Custom Apktool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| You can specify a custom apktool path or command using the ``--apktool-path`` option.
| For example, you can use a script or a specific jar file:
|

.. code:: sh

    $ frida-gadget target.apk --apktool-path ./tools/apktool.bat --sign # Windows
    $ frida-gadget target.apk --apktool-path "java -Xmx16g -jar ~/Download/apktool.jar" --sign # Java with 16GB memory

Custom Apktool Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| You can also specify custom options for apktool decompile and recompile using the ``--decompile-opts`` and ``--recompile-opts`` options.
| For example, you can pass additional flags to apktool:
|

.. code:: sh

    $ frida-gadget target.apk --decompile-opts "--only-main-classes --no-res" --recompile-opts "--force-all" --sign

Contributing
-----------------
.. image:: CONTRIBUTORS.svg
   :target: ./CONTRIBUTORS.svg


.. |Coverage-Status| image:: https://img.shields.io/coveralls/github/ksg97031/frida-gadget/master?logo=coveralls
   :target: https://coveralls.io/github/ksg97031/frida-gadget
.. |Branch-Coverage-Status| image:: https://codecov.io/gh/ksg97031/frida-gadget/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/ksg97031/frida-gadget
.. |Codacy-Grade| image:: https://app.codacy.com/project/badge/Grade/a1e2ef93fd3842e4b9e92971c135ed3f
   :target: https://app.codacy.com/gh/ksg97031/frida-gadget/dashboard
.. |CII Best Practices| image:: https://bestpractices.coreinfrastructure.org/projects/3264/badge
   :target: https://bestpractices.coreinfrastructure.org/projects/3264
.. |GitHub-Status| image:: https://img.shields.io/github/tag/ksg97031/frida-gadget.svg?maxAge=86400&logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/releases
.. |GitHub-Forks| image:: https://img.shields.io/github/forks/ksg97031/frida-gadget.svg?logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/network
.. |GitHub-Stars| image:: https://img.shields.io/github/stars/ksg97031/frida-gadget.svg?logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/stargazers
.. |GitHub-Commits| image:: https://img.shields.io/github/commit-activity/y/ksg97031/frida-gadget.svg?logo=git&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/graphs/commit-activity
.. |GitHub-Issues| image:: https://img.shields.io/github/issues-closed/ksg97031/frida-gadget.svg?logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/issues?q=
.. |GitHub-PRs| image:: https://img.shields.io/github/issues-pr-closed/ksg97031/frida-gadget.svg?logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/pulls
.. |GitHub-Contributions| image:: https://img.shields.io/github/contributors/ksg97031/frida-gadget.svg?logo=github&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/graphs/contributors
.. |GitHub-Updated| image:: https://img.shields.io/github/last-commit/ksg97031/frida-gadget/master.svg?logo=github&logoColor=white&label=pushed
   :target: https://github.com/ksg97031/frida-gadget/pulse
.. |Gift-Casper| image:: https://img.shields.io/badge/dynamic/json.svg?color=ff69b4&label=gifts%20received&prefix=%C2%A3&query=%24..sum&url=https%3A%2F%2Fcaspersci.uk.to%2Fgifts.json
   :target: https://cdcl.ml/sponsor
.. |PyPI-Downloads| image:: https://static.pepy.tech/badge/frida-gadget
   :target: https://pepy.tech/project/frida-gadget
.. |Py-Versions| image:: https://img.shields.io/pypi/pyversions/frida-gadget
   :target: https://pypi.org/project/frida-gadget
.. |Conda-Forge-Status| image:: https://img.shields.io/conda/v/conda-forge/frida-gadget.svg?label=conda-forge&logo=conda-forge
   :target: https://anaconda.org/conda-forge/frida-gadget
.. |Docker| image:: https://img.shields.io/badge/docker-pull-blue.svg?logo=docker&logoColor=white
   :target: https://github.com/ksg97031/frida-gadget/pkgs/container/frida-gadget
.. |Libraries-Dependents| image:: https://img.shields.io/librariesio/dependent-repos/pypi/frida-gadget.svg?logo=koding&logoColor=white
    :target: https://github.com/ksg97031/frida-gadget/network/dependents
.. |OpenHub-Status| image:: https://www.openhub.net/p/frida-gadget/widgets/project_thin_badge?format=gif
   :target: https://www.openhub.net/p/frida-gadget?ref=Thin+badge
.. |awesome-python| image:: https://awesome.re/mentioned-badge.svg
   :target: https://github.com/vinta/awesome-python
.. |LICENCE| image:: https://img.shields.io/pypi/l/frida-gadget.svg
   :target: https://raw.githubusercontent.com/ksg97031/frida-gadget/master/LICENCE
.. |DOI| image:: https://img.shields.io/badge/DOI-10.5281/zenodo.595120-blue.svg
   :target: https://doi.org/10.5281/zenodo.595120
.. |binder-demo| image:: https://mybinder.org/badge_logo.svg
   :target: https://mybinder.org/v2/gh/ksg97031/frida-gadget/master?filepath=DEMO.ipynb
