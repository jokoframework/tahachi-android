package io.github.jokoframework.tahachi.helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import androidx.preference.PreferenceManager;

public class CrudHelper {

    public static final String DESKTOP_LIST = "DESKTOP_LIST";
    private static Context context;

    private static final String LOG_TAG = CrudHelper.class.getSimpleName();

    private static List<String> names = Arrays.asList("Home|https://192.168.9.57:8443",
            "Home|https://192.168.9.57:8443", "MobileAP|https://192.168.43.81:8443",
            "Work|https://10.1.1.149:8443");
    private static SharedPreferences mSharedPreferences;


    public static void save(String name) {
        names.add(name);
        updatePreferences();
    }

    private static void updatePreferences() {
        if (mSharedPreferences != null) {
            mSharedPreferences.edit().putStringSet(DESKTOP_LIST, new HashSet<>(names)).commit();
        }
    }

    public static List<String> getNames() {
        loadNamesFromPreferences();
        return names;
    }

    private static void loadNamesFromPreferences() {
        if (mSharedPreferences != null) {
            Set<String> namesSet = mSharedPreferences.getStringSet(DESKTOP_LIST, new HashSet<>(names));
            names = new ArrayList<>(namesSet);
        }
    }

    public static Boolean update(int position, String newName) {
        try {
            names.remove(position);
            names.add(position, newName);
            updatePreferences();
            return true;
        } catch (Exception e) {
            Log.e(LOG_TAG, e.getMessage(), e);
            return false;
        }
    }

    public static Boolean delete(int position) {
        try {
            names.remove(position);
            updatePreferences();
            return true;
        } catch (Exception e) {
            Log.e(LOG_TAG, e.getMessage(), e);
            return false;

        }
    }

    public static Context getContext() {
        return context;
    }

    public static void setContext(Context context) {
        CrudHelper.context = context;
        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        loadNamesFromPreferences();
        updatePreferences();
    }
}
