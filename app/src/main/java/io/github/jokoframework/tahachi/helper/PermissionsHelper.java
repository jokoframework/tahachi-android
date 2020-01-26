package io.github.jokoframework.tahachi.helper;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.drawable.ColorDrawable;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.core.app.ActivityCompat;
import io.github.jokoframework.tahachi.R;
import pojo.PermissionMessage;

/**
 * Created by nelson on 10/23/17.
 * updated by mgonzalez on 22/01/19.
 */
public class PermissionsHelper {

    private static final int PERMISSION_ALL = 1;
    private static Map<String, PermissionMessage> permissionMessages = new HashMap<>();


    private PermissionsHelper() {
    }

    /**
     * Check if all permissions have been granted
     *
     * @param context
     * @param permissions
     * @return
     */
    public static boolean hasPermissions(Context context, String... permissions) {
        return getMissingPermissions(context, permissions).length > 0 ? false : true;
    }

    public static String[] getMissingPermissions(Context context, String... permissions) {

        List<String> toRet = new ArrayList<>();

        if (context != null && permissions != null && permissions.length > 0) {
            for (String permission : permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) !=
                        PackageManager.PERMISSION_GRANTED) {
                    toRet.add(permission);
                }
            }
        }
        return toRet.toArray(new String[toRet.size()]);
    }


    public static void checkAndAskForPermissions(Activity activity, String... permissions) {
        String[] permissionsRequired = permissions;

        String[] missingPermissions = getMissingPermissions(activity, permissionsRequired);
        if (missingPermissions.length > 0) {
            askForPermission(activity, missingPermissions);
        }
    }

    /**
     * SHows a dialog asking for permissions to the user
     *
     * @param activity
     */
    private static void askForPermission(Activity activity, String... permissions) {

        android.app.AlertDialog.Builder alertBuilder = new android.app.AlertDialog.Builder(activity);
        View infoView = View.inflate(activity,
                R.layout.confirm_dialog, null);
        Button yesButton =
                infoView.findViewById(R.id.confirm_yes);
        Button noButton =
                infoView.findViewById(R.id.confirm_no);
        TextView message =
                infoView.findViewById(R.id.confirm_text);
        TextView title =
                infoView.findViewById(R.id.confirm_title);
        title.setText(R.string.permissions_dialog_title);

        LinearLayout linearLayout = infoView.findViewById(R.id.confirm_dialog_custom);

        for (String permission : permissions) {

            if (permissionMessages.containsKey(permission)) {
                View custom = View.inflate(activity,
                        R.layout.custom_permission_item, null);
                TextView permissionTitle = custom.findViewById(R.id.custom_permission_title);
                TextView permissionDescription = custom.findViewById(R.id.custom_permission_description);
                PermissionMessage permissionMessage = permissionMessages.get(permission);
                permissionTitle.setText(permissionMessage.getTitle());
                permissionDescription.setText(permissionMessage.getDescription());
                linearLayout.addView(custom);
            }
        }

        message.setText(R.string.permissions_dialog_text);
        yesButton.setText(R.string.grant_permission);
        noButton.setText(R.string.prompt_cancel);
        alertBuilder.setView(infoView);
        android.app.AlertDialog alert = alertBuilder.create();
        yesButton.setOnClickListener(view -> {
            ActivityCompat.requestPermissions(activity, permissions, PERMISSION_ALL);
            alert.dismiss();
        });
        noButton.setOnClickListener(view -> alert.dismiss());
        alert.getWindow().setBackgroundDrawable(new ColorDrawable(android.graphics.Color.TRANSPARENT));
        alert.show();
    }

    public static void addMessage(Context context, PermissionMessage message) {
        if (!permissionMessages.containsKey(message.getPermission())) {
            permissionMessages.put(message.getPermission(), message);
        }
    }
}
