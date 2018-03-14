package uitkyk.android.com.uitkyk;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import com.brompwnie.uitkyk.FridaUtils;


public class MainActivity extends AppCompatActivity {

    private TextView textView;
    FridaUtils aUtil;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        aUtil  = new FridaUtils("frida-server-10.6.52-android-arm");

        Button huntMalware = (Button) findViewById(R.id.huntMalware);
        Button getSystemProcs = (Button) findViewById(R.id.getSystemProcs);

        huntMalware.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                textView = (TextView) findViewById(R.id.processListView);
                textView.setText("");
                huntMalware(textView);
            }
        });

        getSystemProcs.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                textView = (TextView) findViewById(R.id.processListView);
                textView.setText("");
                getSystemProcs(textView);
            }
        });

    }


    private void getSystemProcs(TextView textView) {
        UitkykListProcessesTask getAllTheSystemProcs = new UitkykListProcessesTask("127.0.0.1", 27042, textView);
        getAllTheSystemProcs.execute();
    }

    private void huntMalware(TextView textView) {
        TextView pidTextView = (TextView) findViewById(R.id.inputPid);
        int PID = Integer.parseInt(pidTextView.getText().toString());

        try {
            UitkykAnalyzerTask malwareAnalyzer = new UitkykAnalyzerTask("127.0.0.1", 27042, textView, PID);
            malwareAnalyzer.execute();
        } catch (Exception e) {
            Toast.makeText(this, "Error: " + e.toString(), Toast.LENGTH_LONG).show();
        }
    }

    public void refreshFrida(View view) {

        textView = (TextView) findViewById(R.id.processListView);
        textView.setText("");
        aUtil.refreshFrida();
        Toast.makeText(this, "Refreshed" , Toast.LENGTH_LONG).show();

    }


    public void getProcID(View view) {
        TextView processTextView = (TextView) findViewById(R.id.processName);
        String processName=processTextView.getText().toString();
        String pid = aUtil.getPid(processName);
        textView = (TextView) findViewById(R.id.processListView);
        textView.setText("PID for "+processName+": "+pid);
    }
}




