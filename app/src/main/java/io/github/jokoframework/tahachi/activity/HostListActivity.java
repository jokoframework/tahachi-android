package io.github.jokoframework.tahachi.activity;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import io.github.jokoframework.tahachi.R;
import io.github.jokoframework.tahachi.helper.CrudHelper;
import io.github.jokoframework.tahachi.util.MessagesUtil;

public class HostListActivity extends AppCompatActivity {

    private ListView lv;
    private ArrayAdapter<String> adapter;
    private Dialog dialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_host_list);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        lv = (ListView) findViewById(R.id.lv);

        lv.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                if (dialog == null) {
                    initDialog();
                }
                if (!dialog.isShowing()) {
                    displayInputDialog(i);
                } else {
                    dialog.dismiss();
                }
            }
        });

        final FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                displayInputDialog(-1);
            }
        });
        CrudHelper.setContext(this);
        adapter = new ArrayAdapter<String>(HostListActivity.this, android.R.layout.simple_list_item_1, CrudHelper.getNames());
        lv.setAdapter(adapter);
    }

    private void displayInputDialog(final int pos) {
        initDialog();

        final EditText nameEditTxt = (EditText) dialog.findViewById(R.id.nameEditText);
        Button addBtn = (Button) dialog.findViewById(R.id.addBtn);
        Button updateBtn = (Button) dialog.findViewById(R.id.updateBtn);
        Button deleteBtn = (Button) dialog.findViewById(R.id.deleteBtn);

        if (pos == -1) {
            addBtn.setEnabled(true);
            updateBtn.setEnabled(false);
            deleteBtn.setEnabled(false);
        } else {
            addBtn.setEnabled(true);
            updateBtn.setEnabled(true);
            deleteBtn.setEnabled(true);
            nameEditTxt.setText(CrudHelper.getNames().get(pos));
        }

        addBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //GET DATA
                String name = nameEditTxt.getText().toString();

                //VALIDATE
                if (name.length() > 0 && name != null) {
                    //save
                    CrudHelper.save(name);
                    nameEditTxt.setText("");
                    adapter = new ArrayAdapter<String>(HostListActivity.this, android.R.layout.simple_list_item_1, CrudHelper.getNames());
                    lv.setAdapter(adapter);

                } else {
                    MessagesUtil.showWarningMessage(HostListActivity.this, "Name cannot be empty");
                }
            }
        });
        updateBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //GET DATA
                String newName = nameEditTxt.getText().toString();

                //VALIDATE
                if (newName.length() > 0 && newName != null) {
                    //save
                    if (CrudHelper.update(pos, newName)) {
                        nameEditTxt.setText(newName);
                        adapter = new ArrayAdapter<String>(HostListActivity.this, android.R.layout.simple_list_item_1, CrudHelper.getNames());
                        lv.setAdapter(adapter);
                    }

                } else {
                    MessagesUtil.showWarningMessage(HostListActivity.this, "Name cannot be empty");
                }
            }
        });
        deleteBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                //DELETE
                if (CrudHelper.delete(pos)) {
                    nameEditTxt.setText("");
                    adapter = new ArrayAdapter<String>(HostListActivity.this, android.R.layout.simple_list_item_1, CrudHelper.getNames());
                    lv.setAdapter(adapter);
                }
            }
        });

        dialog.show();
    }

    private void initDialog() {
        dialog = new Dialog(this);
        dialog.setTitle("Hosts CRUD");
        dialog.setContentView(R.layout.input_dialog);
    }
}
