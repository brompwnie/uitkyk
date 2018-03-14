package com.brompwnie.uitkyk;


import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;

public class UitkykUtils {

    private String fridaHost;
    private int fridaPort;


    public UitkykUtils(String fridaHost,int fridaPort)
    {
        this.fridaHost=fridaHost;
        this.fridaPort=fridaPort;

    }


    private ArrayList<String> prettifyProcesses(String processList) {
        ArrayList<String> systemProcesses = new ArrayList<>();
        String[] split = processList.split("\0");
        for (String looksie : split) {
            if (looksie.matches("[a-zA-Z]+") | looksie.contains(".")) {
                if (looksie.length() > 3) {
                    System.out.println("DATA-> :" + looksie);
                    systemProcesses.add(looksie);
                }
            }
        }
        return systemProcesses;
    }


    private boolean validateJson(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }

    private String processFridaResponse(String fridaResponse) throws JSONException {
        StringBuilder processed = new StringBuilder();

        ArrayList<String> messageFromScript = this.cleanupMessage(fridaResponse);

        for (String fridaData : messageFromScript) {
            if (this.validateJson(fridaData)) {
                JSONObject jsonObject = new JSONObject(fridaData);
                if (jsonObject.has("payload")) {
                    processed.append(jsonObject.get("payload")).append("\n");
                }
            }

        }
        return processed.toString();
    }


    private ArrayList<String> cleanupMessage(String processList) {
        ArrayList<String> messages = new ArrayList<>();
        String[] split = processList.split("\0");
        for (String looksie : split) {
            if (looksie.matches("[a-zA-Z]+") | looksie.contains(".")) {
                if (looksie.length() > 3) {
                    messages.add(looksie);
                }
            }
        }
        return messages;
    }

    private String doCommand(byte[] dbusMessage, DataOutputStream os, DataInputStream is, int readResponse) throws IOException {
        os.write(dbusMessage);
        os.flush();

        if (readResponse != 0) {
            byte[] bites = new byte[20048];
            int read = is.read(bites);
            byte[] subArray = Arrays.copyOfRange(bites, 0, (read - 1));
            System.out.println("DONE READING BYTES :)" + read);
            String stripResult = "";
            for (byte daBite : subArray) {
                char x = (char) daBite;
                stripResult += x;
            }
            return stripResult;
        } else {
            return "We be done yo!-> \n" + "NO RESPONSE";
        }
    }


    private String justReadFromServer(DataInputStream is) {
        try {
            byte[] bites = new byte[20048];

            int read = is.read(bites);
            byte[] subArray = Arrays.copyOfRange(bites, 0, (read - 1));
            Log.d("READ FROM SERVER", "Num Bytes Read: " + read);
            String stripResult = "";
            for (byte daBite : subArray) {
                char x = (char) daBite;
                stripResult += x;
            }
            return stripResult;

        } catch (Exception e) {
            Log.e("READ FROM SERVER", e.getMessage());
            return "";
        }
    }


    public String analyzeProcess(int processID)
    {

        String response="";

        Socket socket = null;
        DataOutputStream os;
        DataInputStream is;

        try {
            socket = new Socket(this.fridaHost, this.fridaPort);

            os = new DataOutputStream(socket.getOutputStream());
            is = new DataInputStream(socket.getInputStream());

            DataBites dataBites = new DataBites(processID);


            //PART 1
            this.doCommand(dataBites.getAuthMessage(), os, is, 1);

            //PART 2
            System.out.println("STARTING PART 2");
            String part2Response = this.doCommand(dataBites.getAuthAnonymousMessage(), os, is, 1);
            System.out.println(part2Response);

            //PART 3
            System.out.println("STARTING PART 3");
            String part3Result = this.doCommand(dataBites.getBeginMessage(), os, is, 0);
            System.out.println(part3Result);

            //PART 4
            System.out.println("STARTING PART 4");
            String part4Response = this.doCommand(dataBites.getSessionGetAllMessage(), os, is, 1);
            System.out.println(part4Response);


            //PART 5
//            l...........g.....g.......o...../re/frida/HostSession.....s.....EnumerateProcesses........s.....re.frida.HostSession10..
            System.out.println("STARTING PART 5");
            String strPart5Response = this.doCommand(dataBites.getEnumerateProcessesMessage(), os, is, 1);
            System.out.println(strPart5Response);

            //PART 6
            System.out.println("STARTING PART 6");
            String strPart6Response = this.doCommand(dataBites.getAttachToProcess(), os, is, 1);
            System.out.println("LEN SHOULD BE 44 bytes");
            System.out.println("PART 6 RESPONSE: " + strPart6Response);

            //PART 7
            System.out.println("STARTING PART 7");
//            dataBites.setAgent1(agent1);
//            dataBites.setAgent2(agent2);
            String strPart7Response = this.doCommand(dataBites.getAllocateFridaAgentId(), os, is, 1);
            System.out.println("LEN SHOULD BE 48 bytes");
            System.out.println("PART 7 RESPONSE: " + strPart7Response);


            //PART 9
            System.out.println("STARTING PART 9");
            String strPart9Response = this.doCommand(dataBites.getCreateScript1(), os, is, 1);
            System.out.println("LEN SHOULD BE 44 bytes");
            System.out.println("PART 9 RESPONSE: " + strPart9Response);


            //PART 10
            System.out.println("STARTING PART 10");
            String strPart10Response = this.doCommand(dataBites.getLoadScript(), os, is, 1);
            System.out.println("LEN SHOULD BE 268 bytes");
            System.out.println("PART 10 RESPONSE: " + strPart10Response);

            response += "Hunt Feedback\n";
            response += this.processFridaResponse(strPart10Response);


            System.out.println("CHECKING IF DATA IN BUFFER FOR 10.5");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER");
                response += this.processFridaResponse(this.justReadFromServer(is));
            }


            //PART 11
//            RPC CALL ONE
            System.out.println("STARTING PART 11");
            String strPart11Response = this.doCommand(dataBites.getRpcCall1(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 11 RESPONSE: " + strPart11Response);

            if (strPart11Response.contains("[+]") || strPart11Response.contains("[*]")) {
                response += this.processFridaResponse(strPart11Response);
            }


            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER FOR 11.5");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
            }


//            PART 12
//            RPC CALL TWO
            System.out.println("STARTING PART 12");
            String strPart12Response = this.doCommand(dataBites.getRpcCall2(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 12 RESPONSE: " + strPart12Response);

            if (strPart12Response.contains("[+]") || strPart12Response.contains("[*]")) {
                response += this.processFridaResponse(strPart12Response);
            }


            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER FOR 12.5");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
            }


//            PART 13
//            RPC CALL THREE
            System.out.println("STARTING PART 13");
            String strPart13Response = this.doCommand(dataBites.getRpcCall3(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 13 RESPONSE: " + strPart13Response);

            if (strPart13Response.contains("[+]") || strPart13Response.contains("[*]")) {
                response += this.processFridaResponse(strPart13Response);
            }

            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER FOR 13.5");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
            }

//            PART 14
//            RPC CALL FOUR
            System.out.println("STARTING PART 134");
            String strPart14Response = this.doCommand(dataBites.getRpcCall4(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 14 RESPONSE: " + strPart14Response);

            if (strPart14Response.contains("[+]") || strPart14Response.contains("[*]")) {
                response += this.processFridaResponse(strPart14Response);
            }

            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER FOR 14.5");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
            }


//            PART 15
//            DESTROY SCRIPT
            System.out.println("STARTING PART 15: DESTROY SCRIPT");
            String strPart15Response = this.doCommand(dataBites.getDestroyScript(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 15 RESPONSE: " + strPart15Response);

            if (strPart15Response.contains("[+]") || strPart15Response.contains("[*]")) {
                response += this.processFridaResponse(strPart15Response);
            }

            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
                System.out.println("RESPONSE FROM 15.5: " + tmpResponse);
            }

//            PART 16
//            CLOSE SESSION
            System.out.println("STARTING PART 15: DESTROY SCRIPT");
            String strPart16Response = this.doCommand(dataBites.getCloseAgentSession(), os, is, 1);
            System.out.println("LEN SHOULD BE 32 bytes");
            System.out.println("PART 16 RESPONSE: " + strPart16Response);

            if (strPart16Response.contains("[+]") || strPart16Response.contains("[*]")) {
                response += this.processFridaResponse(strPart16Response);
            }

            System.out.println("CHECKING IF DATA IN BUFFER");
            if (is.available() != 0) {
                System.out.println("THERE IS DATA IN THE BUFFER");
                String tmpResponse = this.justReadFromServer(is);
                if (tmpResponse.contains("[+]") || tmpResponse.contains("[*]")) {
                    response += this.processFridaResponse(tmpResponse);
                }
                System.out.println("RESPONSE FROM 16.5: " + tmpResponse);
            } else {
                System.out.println("THERE IS NO DATA IN THE BUFFER!");
            }


        } catch (UnknownHostException e) {
            e.printStackTrace();
            response = "UnknownHostException: " + e.toString();
        } catch (IOException e) {
            e.printStackTrace();
            response = "IOException: " + e.toString();
        } catch (JSONException e) {
            e.printStackTrace();
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return response;

    }

    public String fridaPS()
    {
        String response="";
        Socket socket = null;
        DataOutputStream os;
        DataInputStream is;

        try {
            socket = new Socket(this.fridaHost, this.fridaPort);

            os = new DataOutputStream(socket.getOutputStream());
            is = new DataInputStream(socket.getInputStream());

            byte[] AUTH_Message = {(byte) 0x2e, (byte) 0x41, (byte) 0x55, (byte) 0x54, (byte) 0x48, (byte) 0x0D, (byte) 0x0A};
            this.doCommand(AUTH_Message, os, is, 1);

            //PART 2

            byte[] AUTH_Message2 = {
                    (byte) 0x41, (byte) 0x55, (byte) 0x54, (byte) 0x48,
                    (byte) 0x20, (byte) 0x41, (byte) 0x4e, (byte) 0x4f,
                    (byte) 0x4e, (byte) 0x59, (byte) 0x4d, (byte) 0x4f,
                    (byte) 0x55, (byte) 0x53, (byte) 0x20, (byte) 0x34,
                    (byte) 0x37, (byte) 0x34, (byte) 0x34, (byte) 0x34,
                    (byte) 0x32, (byte) 0x37, (byte) 0x35, (byte) 0x37,
                    (byte) 0x33, (byte) 0x32, (byte) 0x30, (byte) 0x33,
                    (byte) 0x30, (byte) 0x32, (byte) 0x65, (byte) 0x33,
                    (byte) 0x31, (byte) 0x0d, (byte) 0x0a};

            this.doCommand(AUTH_Message2, os, is, 1);


            //PART 3
            byte[] AUTH_Message3 = {
                    (byte) 0x42, (byte) 0x45, (byte) 0x47, (byte) 0x49,
                    (byte) 0x4e, (byte) 0x0D, (byte) 0x0A};
            this.doCommand(AUTH_Message3, os, is, 0);


            //PART 4
            byte[] AUTH_Message4 = {
                    (byte) 0x6c, (byte) 0x01, (byte) 0x00, (byte) 0x01,
                    (byte) 0x1b, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x60, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x08, (byte) 0x01, (byte) 0x67, (byte) 0x00,
                    (byte) 0x01, (byte) 0x73, (byte) 0x00, (byte) 0x00,
//                    \x01\x01\x6f\x00
                    (byte) 0x01, (byte) 0x01, (byte) 0x6f, (byte) 0x00,
//                    \x15\x00\x00\x00\
                    (byte) 0x15, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                   x2f\x72\x65\x2f
                    (byte) 0x2f, (byte) 0x72, (byte) 0x65, (byte) 0x2f,
//                   \x66\x72\x69\x64
                    (byte) 0x66, (byte) 0x72, (byte) 0x69, (byte) 0x64,
                    //           \x61\x2f\x48\x6f
                    (byte) 0x61, (byte) 0x2f, (byte) 0x48, (byte) 0x6f,
//                    \x73\x74\x53\x65
                    (byte) 0x73, (byte) 0x74, (byte) 0x53, (byte) 0x65,
//                    \x73\x73\x69\x6f
                    (byte) 0x73, (byte) 0x73, (byte) 0x69, (byte) 0x6f,
//                    \x6e\x00\x00\x00
                    (byte) 0x6e, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                     \x03\x01\x73\x00
                    (byte) 0x03, (byte) 0x01, (byte) 0x73, (byte) 0x00,
//                    \x06\x00\x00\x00
                    (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                    \x47\x65\x74\x41
                    (byte) 0x47, (byte) 0x65, (byte) 0x74, (byte) 0x41,
//                    \x6c\x6c\x00\x00
                    (byte) 0x6c, (byte) 0x6c, (byte) 0x00, (byte) 0x00,
//                    \x02\x01\x73\x00
                    (byte) 0x02, (byte) 0x01, (byte) 0x73, (byte) 0x00,
//                    \x1f\x00\x00\x00
                    (byte) 0x1f, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                     \x6f\x72\x67\x2e
                    (byte) 0x6f, (byte) 0x72, (byte) 0x67, (byte) 0x2e,
//                     \x66\x72\x65\x65
                    (byte) 0x66, (byte) 0x72, (byte) 0x65, (byte) 0x65,
//                     \x64\x65\x73\x6b
                    (byte) 0x64, (byte) 0x65, (byte) 0x73, (byte) 0x6b,
//                    \x74\x6f\x70\x2e
                    (byte) 0x74, (byte) 0x6f, (byte) 0x70, (byte) 0x2e,
//                    \x44\x42\x75\x73
                    (byte) 0x44, (byte) 0x42, (byte) 0x75, (byte) 0x73,
//                     \x2e\x50\x72\x6f
                    (byte) 0x2e, (byte) 0x50, (byte) 0x72, (byte) 0x6f,
//                    \x70\x65\x72\x74
                    (byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x74,
//                     \x69\x65\x73\x00
                    (byte) 0x69, (byte) 0x65, (byte) 0x73, (byte) 0x00,
//                     \x16\x00\x00\x00
                    (byte) 0x16, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                     \x72\x65\x2e\x66
                    (byte) 0x72, (byte) 0x65, (byte) 0x2e, (byte) 0x66,
//                     \x72\x69\x64\x61
                    (byte) 0x72, (byte) 0x69, (byte) 0x64, (byte) 0x61,
//                    \x2e\x48\x6f\x73
                    (byte) 0x2e, (byte) 0x48, (byte) 0x6f, (byte) 0x73,
//                    \x74\x53\x65\x73
                    (byte) 0x74, (byte) 0x53, (byte) 0x65, (byte) 0x73,
//                     \x73\x69\x6f\x6e
                    (byte) 0x73, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
//                    \x31\x30\x00
                    (byte) 0x31, (byte) 0x30, (byte) 0x00
            };

            this.doCommand(AUTH_Message4, os, is, 1);

            //PART 5
            byte[] AUTH_Message5 = {
//                   \x6c\x01\x00\x01
                    (byte) 0x6c, (byte) 0x01, (byte) 0x00, (byte) 0x01,
//                   \x00\x00\x00\x00
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                  \x02\x00\x00\x00
                    (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                \x67\x00\x00\x00
                    (byte) 0x67, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                   \x08\x01\x67\x00
                    (byte) 0x08, (byte) 0x01, (byte) 0x67, (byte) 0x00,
//                    \x00\x00\x00\x00
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                   \x01\x01\x6f\x00
                    (byte) 0x01, (byte) 0x01, (byte) 0x6f, (byte) 0x00,
//                    \x15\x00\x00\x00
                    (byte) 0x15, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                   \x2f\x72\x65\x2f
                    (byte) 0x2f, (byte) 0x72, (byte) 0x65, (byte) 0x2f,
//                  \x66\x72\x69\x64
                    (byte) 0x66, (byte) 0x72, (byte) 0x69, (byte) 0x64,
//                    \x61\x2f\x48\x6f
                    (byte) 0x61, (byte) 0x2f, (byte) 0x48, (byte) 0x6f,
//                    \x73\x74\x53\x65
                    (byte) 0x73, (byte) 0x74, (byte) 0x53, (byte) 0x65,
//                    \x73\x73\x69\x6f
                    (byte) 0x73, (byte) 0x73, (byte) 0x69, (byte) 0x6f,
//                   \x6e\x00\x00\x00
                    (byte) 0x6e, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                    \x03\x01\x73\x00
                    (byte) 0x03, (byte) 0x01, (byte) 0x73, (byte) 0x00,
//                   \x12\x00\x00\x00
                    (byte) 0x12, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                    \x45\x6e\x75\x6d
                    (byte) 0x45, (byte) 0x6e, (byte) 0x75, (byte) 0x46d,
//                    \x65\x72\x61\x74
                    (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x74,
//                   \x65\x50\x72\x6f
                    (byte) 0x65, (byte) 0x50, (byte) 0x72, (byte) 0x6f,
//                    \x63\x65\x73\x73
                    (byte) 0x63, (byte) 0x65, (byte) 0x73, (byte) 0x73,
//                    x65\x73\x00\x00
                    (byte) 0x65, (byte) 0x73, (byte) 0x00, (byte) 0x00,
//                     \x00\x00\x00\x00
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                     \x02\x01\x73\x00
                    (byte) 0x02, (byte) 0x01, (byte) 0x73, (byte) 0x00,
//                    \x16\x00\x00\x00
                    (byte) 0x16, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//                    \x72\x65\x2e\x66
                    (byte) 0x72, (byte) 0x65, (byte) 0x2e, (byte) 0x66,
//                     \x72\x69\x64\x61
                    (byte) 0x72, (byte) 0x69, (byte) 0x64, (byte) 0x61,
//                    \x2e\x48\x6f\x73
                    (byte) 0x2e, (byte) 0x48, (byte) 0x6f, (byte) 0x73,
//                     \x74\x53\x65\x73
                    (byte) 0x74, (byte) 0x53, (byte) 0x65, (byte) 0x73,
//                    \x73\x69\x6f\x6e
                    (byte) 0x73, (byte) 0x69, (byte) 0x6f, (byte) 0x6e,
//                    \x31\x30\x00\x00
                    (byte) 0x31, (byte) 0x30, (byte) 0x00, (byte) 0x00,
            };
            String strPart5Response = this.doCommand(AUTH_Message5, os, is, 1);

            ArrayList<String> allSystemProcesses = this.prettifyProcesses(strPart5Response);
            response += "\n\nACTIVE PROCESS LIST: " + allSystemProcesses.size() + "\n";
            for (String proc : allSystemProcesses) {
                response += "\n" + proc;
            }

        } catch (UnknownHostException e) {
            e.printStackTrace();
            response = "UnknownHostException: " + e.toString();
        } catch (IOException e) {
            e.printStackTrace();
            response = "IOException: " + e.toString();
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return response;
    }


    public String getFridaHost() {
        return fridaHost;
    }

    public void setFridaHost(String fridaHost) {
        this.fridaHost = fridaHost;
    }

    public int getFridaPort() {
        return fridaPort;
    }

    public void setFridaPort(int fridaPort) {
        this.fridaPort = fridaPort;
    }
}
