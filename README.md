# uitkyk
Uitkyk is a custom Android Frida libary which provides an API to analyze Android applications for malicious activity. This is a PoC library to illustrate the capabilities of performing runtime analysis on Android. Additionally Uitkyk is a collection of resources to assist in the identification of malicious Android applications at runtime. For more information, please see the TROOPERS18 talk here https://troopers.de/troopers18/agenda/uc9azv/

## This Repo
The folder "Frida Scripts" contains some basic Frida scripts to assist in the runtime analysis of Android applications.
The folder "Android Library" contains the custom Android Frida library which can be used by Android applications to interact with Frida server instances. The folder "UitkykDemoApp" contains a demo Android application which utilizes the Uitkyk library. 

## Uitkyk Usage
To use the Uitkyk library, add the module to your Android application as a regular Android module. Currently there are two methods supported. To run the Frida equivelant of "frida-ps -U", use:

```
UitkykUtils uitkykUtils = new UitkykUtils(fridaHost, fridaPort);
uitkykUtils.analyzeProcess(this.pid);
```

To run the Frida equivelant of "frida -U -l AnalyzingHeapForObjects.js com.an.android.app", use:
```
UitkykUtils uitkykUtils= new UitkykUtils(fridaHost,fridaPort);
uitkykUtils.fridaPS();
```

## Requirements
A Frida Server instance is required to be running on the device. The defaults will suffice but a custom host and IP can be used.

## Scripts
The scripts located in the Scripts folder can be run as following:

```
frida -U -l AnalyzingHeapForObjects.js com.an.android.app
```

```
frida -U -l CatchingRuntimeExec.js com.an.android.app
```

## Uitkyk Demo App
This application uses the Uitkyk library. Import the library into the app to ensure the application builds and runs. To ensure that the demo app runs, a local instance of Frida Server is required to be running locally on the device.

## Some Videos
The videos used in the TROOPERS18 talk can be found here https://goo.gl/k6BNBq

## This repo will be updated regularly while I am at Troopers, please expect delays
