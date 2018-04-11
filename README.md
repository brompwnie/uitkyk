# Introduction

By Chris Le Roy (@brompwnie)

Uitkyk is a framework that allows you to identify Android malware according to the instantiated objects on the heap for a specific Android process.

Uitkyk was launched at Troopers18 and the talk and slides can be found here https://troopers.de/troopers18/agenda/uc9azv/
Videos showing Uitkyk in action can be found on YouTube here https://www.youtube.com/channel/UCqCZRfUpl2azw8ZfvCiOIKA

# What does it do
Uitkyk scans the heap of a specific Android process using custom Frida scripts to identify malicous behaviour according to the objects instantiated by a specific Android process.

# How to use Uitkyk
Uitkyk can be used in multiple ways. Firstly as a Android library with existing Android applications which can be done by adding the code in the "Android Library" folder or the AAR release as a library to your Android application. Secondly as a standalone application which can be done by building and running the Android application located in the "UitkykDemoApp" folder. Thirdly, Uitkyk can implemented using the Frida CLI by running the Frida scripts located in the "FridaScripts" folder.

# Requirements
A Frida Server instance is required to be running on the device. By default Uitkyk makes use of Frida running on tcp:host=127.0.0.1,port=27042 but a custom host and IP can be used.

To run the Frida server binary on your device, you could run the command:
``` 
./fridaBinary &&
```

# Uitkyk Library Usage
Make sure you have a Frida server instance running as described in the Requirements section. To use the Uitkyk library, add the module to your Android application as a regular Android module by either adding the AAR located in the Release section or the source code located in the "Android Library" folder. To run the Frida equivelant of "frida-ps -U", use:

```
UitkykUtils uitkykUtils = new UitkykUtils(fridaHost, fridaPort);
String results = uitkykUtils.analyzeProcess(this.pid);
```

To run the Frida equivelant of "frida -U -l AnalyzingHeapForObjects.js com.an.android.app", use:
```
UitkykUtils uitkykUtils= new UitkykUtils(fridaHost,fridaPort);
String results = uitkykUtils.fridaPS();
```

The API calls return a String which contains the output of the scans which can be used for further analysis.

# Uitkyk Application Usage
First, make sure you have implemented the Requirements section. To use the Uitkyk application, either download the prebuilt APK located in the release section or build the APK from the source code located in the "UitkykDemoApp" folder. Once the apk is installed, simply run the application and provide the process ID for the process you want to analyze.


## Uitky Scripts
The scripts located in the Scripts folder can be run as following:

```
frida -U -l AnalyzingHeapForObjects.js com.an.android.app
```

```
frida -U -l CatchingRuntimeExec.js com.an.android.app
```

# License

Uitkyk is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0).
