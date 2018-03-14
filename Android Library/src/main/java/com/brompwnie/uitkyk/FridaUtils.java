package com.brompwnie.uitkyk;

import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class FridaUtils {

    private static final String TAG = FridaUtils.class.getName();
    private String fridaBinary;

    public FridaUtils(String binaryName)
    {
        this.fridaBinary=binaryName;
    }


    public String getFridaBinary() {
        return fridaBinary;
    }

    public void setFridaBinary(String fridaBinary) {
        this.fridaBinary = fridaBinary;
    }

    public void refreshFrida() {
        Log.v(TAG, "Refreshing FRIDA");
        this.killFrida();
        this.runFrida();
    }

    private void runFrida() {
        Log.v(TAG, "Running FRIDA");
        this.runShellCommand("su -c /data/local/tmp/"+this.fridaBinary+" &");
    }

    public String getPid(String processName)
    {
        String processPID="";
        String psResult = this.runShellCommand("su -c ps | grep "+processName);
        String[] splited = psResult.split("\\s+");

        if (splited.length >= 8) {
            processPID = splited[1];
            Log.v(TAG, "Found PID for: " + processPID);
        }
        return processPID;
    }


    private void killFrida() {
        Log.v(TAG, "Killing Frida");
        String s = this.runShellCommand("ps | grep frida");
        String[] splited = s.split("\\s+");

        if (splited.length >= 9) {
            String fridaPid = splited[9];
            this.runShellCommand("su -c kill -9 " + fridaPid);
            Log.v(TAG, "FRIDA killed with pid: " + fridaPid);
        } else {
            Log.v(TAG, "FRIDA not running, nothing to kill");
        }
    }

    private String runShellCommand(String shellCommand) {
        try {
            Process process = Runtime.getRuntime().exec(shellCommand);
            InputStreamReader reader = new InputStreamReader(process.getInputStream());
            BufferedReader bufferedReader = new BufferedReader(reader);
            int numRead;
            char[] buffer = new char[5000];
            StringBuilder commandOutput = new StringBuilder();
            while ((numRead = bufferedReader.read(buffer)) > 0) {
                commandOutput.append(buffer, 0, numRead);
            }
            bufferedReader.close();
            process.waitFor();
            return commandOutput.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
