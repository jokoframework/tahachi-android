package io.github.jokoframework.tahachi.util;

import android.app.Activity;
import android.app.Dialog;
import android.content.res.Resources;
import android.util.Log;
import android.view.ViewGroup;

import com.irozon.sneaker.Sneaker;

import io.github.jokoframework.tahachi.MainActivity;
import io.github.jokoframework.tahachi.R;

/**
 * Created by mgonzalez on 10/05/2018
 * afeltes 30/12/2019
 */
public class MessagesUtil {

    public static final String HA_OCURRIDO_UN_ERROR = "Ha ocurrido un error";
    public static final int DEFAULT_MESSAGE_DURATION = 4000;
    private static String LOG_TAG = MessagesUtil.class.getSimpleName();

    private MessagesUtil() {
    }

    private static Dialog errorDialog;

    public static void showMessage(Activity baseActivity, String message,
                                   boolean isBackgroundOperation, boolean isDialog,
                                   int color) {

        if (baseActivity != null) {
            String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;

            Resources resources = baseActivity.getResources();
            float iconSize = resources.getDimension(R.dimen.message_error_header_icon_size);

            Sneaker.with(baseActivity)
                    .setMessage(message, R.color.white)
                    .autoHide(true)
                    .setDuration(DEFAULT_MESSAGE_DURATION)
                    .setIcon(R.drawable.alert, R.color.white, false)
                    .setIconSize(Math.round(iconSize))
                    .sneak(color);
        } else {
            Log.e(LOG_TAG, "Context is null");
        }
    }

    public static void showErrorMessage(Activity baseActivity, String message) {
        String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;
        if (baseActivity != null && !baseActivity.isFinishing()) {
            showMessage(baseActivity, finalMessage, false, false,
                    R.color.text_color_error);
        }
    }

    public static void showWarningMessage(Activity baseActivity, String message) {
        String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;
        if (baseActivity != null && !baseActivity.isFinishing()) {
            showMessage(baseActivity, finalMessage, false, false,
                    R.color.text_color_warning);
        }
    }

    public static void showErrorMessageViewGroup(Activity activity, ViewGroup viewGroup,
                                                 String message, boolean isDialog, int color) {

        Resources resources = activity.getResources();
        float iconSize = resources.getDimension(R.dimen.message_error_header_icon_size);

        Sneaker.with(viewGroup)
                .setMessage(message, R.color.white)
                .autoHide(true)
                .setDuration(DEFAULT_MESSAGE_DURATION)
                .setIcon(R.drawable.alert, R.color.white, false)
                .setIconSize(Math.round(iconSize))
                .sneak(color);
    }

    public static void showMessage(Activity activity, ViewGroup viewGroup,
                                   String message, boolean isDialog) {
        String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;
        if (activity != null && !activity.isFinishing()) {
            showErrorMessageViewGroup(activity, viewGroup, finalMessage, isDialog,
                    R.color.text_color_error);
        }
    }

    public static void showWarningMessage(Activity activity, ViewGroup viewGroup,
                                          String message, boolean isDialog) {
        String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;
        if (activity != null && !activity.isFinishing()) {
            showErrorMessageViewGroup(activity, viewGroup, finalMessage, isDialog,
                    R.color.text_color_warning);
        }
    }


    public static void showInfoMessage(MainActivity activity, String message) {
        String finalMessage = message != null ? message : HA_OCURRIDO_UN_ERROR;
        if (activity != null && !activity.isFinishing()) {
            showMessage(activity, finalMessage, false, false,
                    R.color.text_color_info);
        }
    }
}
