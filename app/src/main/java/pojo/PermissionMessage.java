package pojo;

import java.security.Permission;

/**
 * Created by mgonzalez on 22/01/2019
 */
public class PermissionMessage {

    private String title;
    private String description;
    private String permission;

    public PermissionMessage(String permission, String title, String description) {
        setPermission(permission);
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
