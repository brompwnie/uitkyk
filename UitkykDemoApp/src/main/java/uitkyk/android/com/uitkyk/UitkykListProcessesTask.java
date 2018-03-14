package uitkyk.android.com.uitkyk;

import android.os.AsyncTask;
import android.widget.TextView;

import com.brompwnie.uitkyk.UitkykUtils;

public class UitkykListProcessesTask extends AsyncTask<Object, Object,String> {

    private String fridaHost;
    private int fridaPort;
    private TextView textResponse;

    UitkykListProcessesTask(String host, int port, TextView textResponse) {
        fridaHost = host;
        fridaPort = port;
        this.textResponse = textResponse;
    }


    @Override
    protected String doInBackground(Object... params) {
        UitkykUtils uitkykUtils= new UitkykUtils(fridaHost,fridaPort);
        return uitkykUtils.fridaPS();
    }


    @Override
    protected void onPostExecute(String result) {
        textResponse.setText(result);
        super.onPostExecute(result);
    }
}
