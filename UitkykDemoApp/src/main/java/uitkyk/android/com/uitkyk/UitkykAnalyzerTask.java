package uitkyk.android.com.uitkyk;

import android.os.AsyncTask;
import android.widget.TextView;

import com.brompwnie.uitkyk.UitkykUtils;

public class UitkykAnalyzerTask extends AsyncTask<Object, Object, String> {

    private String fridaHost;
    private int fridaPort;
    private int pid;
    private TextView textResponse;


    public UitkykAnalyzerTask(String host, int port, TextView textResponse, int pid) {
        this.fridaHost = host;
        this.fridaPort = port;
        this.textResponse = textResponse;
        this.pid = pid;
    }


    @Override
    protected String doInBackground(Object... objects) {
        UitkykUtils uitkykUtils = new UitkykUtils(fridaHost, fridaPort);
        return uitkykUtils.analyzeProcess(this.pid);
    }


    @Override
    protected void onPostExecute(String result) {
        textResponse.setText(result);
        super.onPostExecute(result);
    }
}
