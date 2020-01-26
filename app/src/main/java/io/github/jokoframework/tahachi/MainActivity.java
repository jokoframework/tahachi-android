/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
package io.github.jokoframework.tahachi;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageButton;
import android.widget.TextView;

import com.auth0.android.jwt.JWT;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.preference.PreferenceManager;
import io.github.jokoframework.tahachi.activity.SettingsActivity;
import io.github.jokoframework.tahachi.dto.JokoBaseResponse;
import io.github.jokoframework.tahachi.dto.LoginResponse;
import io.github.jokoframework.tahachi.dto.request.JokoLoginRequest;
import io.github.jokoframework.tahachi.exceptions.TahachiException;
import io.github.jokoframework.tahachi.helper.CrudHelper;
import io.github.jokoframework.tahachi.helper.PermissionsHelper;
import io.github.jokoframework.tahachi.repository.JokoBackendService;
import io.github.jokoframework.tahachi.security.FingerprintAuthenticationDialogFragment;
import io.github.jokoframework.tahachi.util.MessagesUtil;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import pojo.PermissionMessage;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import retrofit2.converter.gson.GsonConverterFactory;

/**
 * @author afeltes
 * Based on https://github.com/googlearchive/android-FingerprintDialog
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    private static final String SECRET_MESSAGE = "Very secret message";
    private static final String KEY_NAME_NOT_INVALIDATED = "key_not_invalidated";
    public static final String DEFAULT_KEY_NAME = "default_key";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String REFRESH_TOKEN = "refreshToken";
    private static final String MAP_SSID_TO_HOST = "mapSSID2Host";
    public static final String UNKNOWN_SSID = "<unknown ssid>";
    public static final String BLACKLIST = "blacklist";
    private boolean locking;

    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private SharedPreferences mSharedPreferences;
    private Retrofit retrofit;
    private JokoBackendService jokoBackendService;
    private List<String> trustedHosts;
    private String username;
    private String password;
    private boolean mPermissionDenied;
    private String baseURL;
    private String currentSSID;
    private TextView console;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        console = findViewById(R.id.console);
        boolean initialized = initSecureCredentials();
        if (initialized) {
            MessagesUtil.showErrorMessage(this,
                    "Failed secure storage initialization. \nPlease check your fingerprint settings");
        } else {
            CrudHelper.setContext(this);
            checkForPermissions();
            initializeRestServices();
        }
    }

    private void checkForPermissions() {
        boolean hasPermissions = PermissionsHelper.hasPermissions(this,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION);
        if (!hasPermissions) {
            PermissionMessage permissionMessage =
                    new PermissionMessage(Manifest.permission.ACCESS_FINE_LOCATION,
                            getString(R.string.title_access_fine_location),
                            getString(R.string.description_access_fine_location));
            PermissionsHelper.addMessage(this, permissionMessage);
            PermissionsHelper.checkAndAskForPermissions(this,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION);
        }
    }

    private boolean initSecureCredentials() {
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            throw new TahachiException("Failed to get an instance of KeyStore", e);
        }
        try {
            mKeyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new TahachiException("Failed to get an instance of KeyGenerator", e);
        }
        Cipher defaultCipher;
        Cipher cipherNotInvalidated;
        try {
            defaultCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipherNotInvalidated = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new TahachiException("Failed to get an instance of Cipher", e);
        }
        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        KeyguardManager keyguardManager = getSystemService(KeyguardManager.class);
        FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);
        ImageButton unlockButton = findViewById(R.id.unlock);
        ImageButton lockButton = findViewById(R.id.lock);


        lockButton.setEnabled(true);
        lockButton.setOnClickListener(
                new LockUnlockButtonClickListener(cipherNotInvalidated,
                        KEY_NAME_NOT_INVALIDATED, true));

        if (!keyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            showNoFingerPrintAvailable("\nSecure lock screen hasn't set up.\n", "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint");
            unlockButton.setEnabled(false);
            lockButton.setEnabled(false);
            return true;
        }

        // Now the protection level of USE_FINGERPRINT permission is normal instead of dangerous.
        // See http://developer.android.com/reference/android/Manifest.permission.html#USE_FINGERPRINT
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            unlockButton.setEnabled(false);
            // This happens when no fingerprints are registered.
            showNoFingerPrintAvailable("Go to 'Settings -> Security -> Fingerprint' and register at least one", " fingerprint");
            return true;
        }
        createKey(DEFAULT_KEY_NAME, true);
        createKey(KEY_NAME_NOT_INVALIDATED, false);
        unlockButton.setEnabled(true);
        unlockButton.setOnClickListener(
                new LockUnlockButtonClickListener(defaultCipher, DEFAULT_KEY_NAME, false));
        return false;
    }

    private void showNoFingerPrintAvailable(String s, String s2) {
        MessagesUtil.showErrorMessage(this,
                s +
                        s2);
    }

    private void initializeRestServices() {
        Map<String, String> ssidToHost = getSSID2HostMap();
        Set<String> blacklist = mSharedPreferences.getStringSet(BLACKLIST, new TreeSet<>());
        String ssid = null;
        String defaultDesktop = getString(R.string.default_desktop);
        validateCredentials();
        WifiManager wifiManager =
                (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        WifiInfo wifiInfo;
        boolean rememberSSID = mSharedPreferences.getBoolean(getString(R.string.remember_ssid),
                false);
        if(!rememberSSID) {
            clearStoredHosts();
        }

        wifiInfo = wifiManager.getConnectionInfo();
        if (wifiInfo.getSupplicantState() == SupplicantState.COMPLETED) {
            ssid = wifiInfo.getSSID();
            setCurrentSSID(ssid);
            if (rememberSSID && StringUtils.isNotEmpty(ssid) && !UNKNOWN_SSID.equalsIgnoreCase(ssid)) {
                if (ssidToHost.containsKey(ssid)) {
                    defaultDesktop = ssidToHost.get(ssid);
                    if (!blacklist.contains(defaultDesktop)) {
                        MessagesUtil.showInfoMessage(this,
                                String.format("\nReutilizando para SSID %s, host: %s", ssid,
                                        defaultDesktop));
                    } else {
                        defaultDesktop = getNewDesktopURL(ssidToHost, ssid, defaultDesktop);
                    }
                } else {
                    defaultDesktop = getNewDesktopURL(ssidToHost, ssid, defaultDesktop);
                }
            } else {
                clearStoredHosts();
                //mSharedPreferences.edit().putStringSet(BLACKLIST,new TreeSet<>()).commit();
                defaultDesktop = getDesktopFromPreference(defaultDesktop);
            }
        }
        createJokoService(defaultDesktop);
        renewTokens();
    }

    private void clearStoredHosts() {
        mSharedPreferences.edit().putStringSet(BLACKLIST, new TreeSet<>()).commit();
        mSharedPreferences.edit().putString(MAP_SSID_TO_HOST,
                new Gson().toJson(new HashMap<>())).commit();
    }

    private String getNewDesktopURL(Map<String, String> ssidToHost, String ssid, String defaultDesktop) {
        defaultDesktop = getDesktopFromPreference(defaultDesktop);
        ssidToHost.put(ssid, defaultDesktop);
        mSharedPreferences.edit().putString(MAP_SSID_TO_HOST,
                new Gson().toJson(ssidToHost)).commit();
        return defaultDesktop;
    }

    private void setCurrentSSID(String ssid) {
        this.currentSSID = ssid;
    }

    private String getDesktopFromPreference2(String defaultDesktop) {
        String baseUrlHash = mSharedPreferences
                .getString(getString(R.string.host_selected), getString(R.string.default_desktop));
        if (mSharedPreferences.getBoolean(getString(R.string.use_default_desktop), false)) {
            String defaultHost = mSharedPreferences.getString(getString(R.string.default_desktop_flag), defaultDesktop);
            defaultDesktop = defaultHost;
        } else {
            defaultDesktop = baseUrlHash;
        }
        return defaultDesktop;
    }

    private String getDesktopFromPreference(String defaultDesktop) {
        String desktop = getString(R.string.default_desktop);
        Set<String> baseUrlHash = mSharedPreferences
                .getStringSet(CrudHelper.DESKTOP_LIST, new HashSet<>(Arrays.asList(desktop)));
        Set<String> blacklist = mSharedPreferences.getStringSet(BLACKLIST, new TreeSet<>());
        Iterator<String> hosts = baseUrlHash.iterator();

        while (hosts.hasNext()) {
            String pair = hosts.next();
            if (pair.indexOf('|') >= 0) {
                String[] labelHost = pair.split("\\|");
                desktop = labelHost[1];
                if (!blacklist.contains(desktop)) {
                    break;
                } else {
                    Log.d(TAG, String.format("Skipping blacklisted: %s", desktop));
                }
            }
        }
        return desktop;
    }

    private Map<String, String> getSSID2HostMap() {
        String mapString = mSharedPreferences.getString(MAP_SSID_TO_HOST, "");
        Type type = new TypeToken<HashMap<String, String>>() {
        }.getType();
        Map<String, String> map = new Gson().fromJson(mapString, type);
        if (map == null) {
            map = new HashMap<>();
        }
        return map;
    }

    private void renewTokens() {
        JokoLoginRequest loginRequest = new JokoLoginRequest(username, password);
        if (needsToRenewToken(ACCESS_TOKEN)) {
            Call<LoginResponse> response = jokoBackendService.login(loginRequest);
            response.enqueue(new Callback<LoginResponse>() {
                @Override
                public void onResponse(Call<LoginResponse> call, Response<LoginResponse> response) {
                    String msg;
                    if (response.code() == 200 && response.isSuccessful()) {
                        LoginResponse loginResponse = response.body();
                        msg = String.format("Request correctamente invocado HTTP CODE: %s", response.code());
                        Log.i(TAG, msg);
                        mSharedPreferences.edit().putString(ACCESS_TOKEN, loginResponse.getSecret()).commit();
                        refreshToken();
                    } else {
                        mSharedPreferences.edit().remove(ACCESS_TOKEN).commit();
                        msg = String.format("No se pudo ejecutar correctamente el request. HTTP Code recibido: %s", response.code());
                        Log.i(TAG, msg);
                    }
                    getConsole().setText(msg);
                    Log.d(TAG, response.toString());
                }

                @Override
                public void onFailure(Call<LoginResponse> call, Throwable t) {
                    Log.e(TAG, "No se pudo completar el request", t);
                    mSharedPreferences.edit().remove(ACCESS_TOKEN).commit();
                    if (t instanceof SocketTimeoutException) {
                        getConsole().setText(t.getMessage());
                        SocketTimeoutException exception = (SocketTimeoutException) t;
                        Set<String> blacklist = mSharedPreferences.getStringSet("blacklist",
                                new TreeSet<>());
                        blacklist.add(getBaseURL());
                        mSharedPreferences.edit().putStringSet(BLACKLIST, blacklist).commit();
                    }
                }
            });
        }
    }

    private void setConsoleText(String message) {
        console.setText(message);
    }

    private TextView getConsole() {
        if (console == null) {
            console = findViewById(R.id.console);
        }
        return console;
    }

    public boolean needsToRenewToken(String preferenceName) {
        boolean renew = true;
        String accessToken = mSharedPreferences.getString(preferenceName, null);
        if (StringUtils.isNotEmpty(accessToken)) {
            Date rightThisMinute = new Date();
            JWT jwt = new JWT(accessToken);
            renew = rightThisMinute.after(jwt.getExpiresAt());
        }
        return renew;
    }

    private void refreshToken() {
        String accessToken = mSharedPreferences.getString(ACCESS_TOKEN, null);
        if (needsToRenewToken(REFRESH_TOKEN)) {
            Call<LoginResponse> refreshResponse = jokoBackendService.userAccess(accessToken);
            refreshResponse.enqueue(new Callback<LoginResponse>() {
                @Override
                public void onResponse(Call<LoginResponse> call, Response<LoginResponse> response) {
                    if (response.code() == 200 && response.isSuccessful()) {
                        LoginResponse refreshResponse = response.body();
                        mSharedPreferences.edit().putString(REFRESH_TOKEN, refreshResponse.getSecret()).commit();
                        Log.i(TAG, String.format("Request correctamente invocado HTTP CODE: %s", response.code()));
                    } else {
                        mSharedPreferences.edit().remove(REFRESH_TOKEN).commit();
                        Log.i(TAG, String.format("No se pudo ejecutar correctamente el request. HTTP Code recibido: %s", response.code()));
                    }
                    Log.d(TAG, response.toString());
                }

                @Override
                public void onFailure(Call<LoginResponse> call, Throwable t) {
                    Log.e(TAG, "No se pudo completar el request", t);
                    mSharedPreferences.edit().remove(REFRESH_TOKEN).commit();
                }
            });
        }
    }

    private void validateCredentials() {
        username = mSharedPreferences
                .getString(getString(R.string.username), null);
        password = mSharedPreferences
                .getString(getString(R.string.password), null);

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            MessagesUtil.showErrorMessage(this, "Go to settings to add valid credentials");
        }
    }

    private void createJokoService(String baseUrl) {
        X509TrustManager trustManager;
        SSLSocketFactory sslSocketFactory;
        try {
            trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new TahachiException("No se pudo agregar el certificado SSL default.", e);
        }

        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        // set your desired log level
        logging.level(HttpLoggingInterceptor.Level.HEADERS);

        OkHttpClient.Builder httpClient =
                new OkHttpClient.Builder().sslSocketFactory(sslSocketFactory, trustManager)
                        .hostnameVerifier((hostname, sslSession) -> {
                            trustedHosts = Arrays.asList(
                                    getResources().getStringArray(R.array.trustedHosts));
                            boolean isTrusted = false;
                            for (String host : trustedHosts) {
                                isTrusted = host.indexOf(hostname) >= 0;
                                if (isTrusted) {
                                    Log.d(TAG, String.format("Confiando en host: %s", hostname));
                                    break;
                                }
                            }
                            return isTrusted;
                        });
        // add your other interceptors …

        // add logging as last interceptor
        httpClient.addInterceptor(logging);  // <-- this is the important line!
        retrofit = new Retrofit.Builder()
                .baseUrl(baseUrl)
                .addConverterFactory(GsonConverterFactory.create())
                .addCallAdapterFactory(RxJava2CallAdapterFactory.create())
                .client(httpClient.build())
                .build();
        setBaseURL(baseUrl);
        jokoBackendService = retrofit.create(JokoBackendService.class);
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the
     * {@link #createKey(String, boolean)} method.
     *
     * @param keyName the key name to init the cipher
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher(Cipher cipher, String keyName) {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(keyName, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new TahachiException("Failed to init Cipher", e);
        }
    }

    /**
     * Proceed the tahachi operation
     *
     * @param withFingerprint {@code true} if the tahachi was made by using a fingerprint
     * @param cryptoObject    the Crypto object
     */
    public void onTahachid(boolean withFingerprint,
                           @Nullable FingerprintManager.CryptoObject cryptoObject) {
        initializeRestServices();
        if (withFingerprint) {
            // If the user has authenticated with fingerprint, verify that using cryptography and
            // then show the confirmation message.
            if (cryptoObject != null) {
                tryEncrypt(cryptoObject.getCipher());
            } else {
                throw new TahachiException("No se pudieron obtener las credenciales de huella.");
            }
        } else {
            // Authentication happened with backup password. Just show the confirmation message.
            showConfirmation(null, true);
        }
    }

    // Show confirmation, if fingerprint was used show crypto information.
    private void showConfirmation(byte[] encrypted, final boolean retryOn401) {
        Call<JokoBaseResponse> response;
        validateCredentials();
        String jokoToken = mSharedPreferences.getString(REFRESH_TOKEN, null);
        TextView textMessageLock = findViewById(R.id.locked_message);
        TextView textMessageUnlock = findViewById(R.id.unlocked_message);
        if (isLocking()) {
            response = jokoBackendService.lockDesktop(jokoToken);
            textMessageUnlock.setVisibility(View.GONE);
            textMessageLock.setVisibility(View.VISIBLE);
            textMessageLock.setText(getString(R.string.unlocked, getCurrentSSID(), getBaseURL()));
        } else {
            response = jokoBackendService.unlockDesktop(jokoToken);
            textMessageLock.setVisibility(View.GONE);
            textMessageUnlock.setVisibility(View.VISIBLE);
            textMessageUnlock.setText(getString(R.string.locked, getCurrentSSID(), getBaseURL()));
        }
        response.enqueue(new Callback<JokoBaseResponse>() {
            @Override
            public void onResponse(Call<JokoBaseResponse> call, Response<JokoBaseResponse> response) {
                if (response.code() == 200) {
                    Log.i(TAG, String.format("Request correctamente invocado HTTP CODE: %s", response.code()));
                } else if (response.code() == 401 && retryOn401) {
                    renewTokens();
                    showConfirmation(encrypted, false);
                } else {
                    Log.i(TAG, String.format("No se pudo ejecutar correctamente el request. HTTP Code recibido: %s", response.code()));
                }
                Log.d(TAG, response.toString());
            }

            @Override
            public void onFailure(Call<JokoBaseResponse> call, Throwable t) {
                Log.e(TAG, "No se pudo completar el request", t);
            }
        });
        if (encrypted != null) {
            Log.d(TAG, "Credenciales correctas.");
        }
    }

    private String getCurrentSSID() {
        return currentSSID;
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    private void tryEncrypt(Cipher cipher) {
        try {
            byte[] encrypted = cipher.doFinal(SECRET_MESSAGE.getBytes());
            showConfirmation(encrypted, true);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            showNoFingerPrintAvailable("Failed to encrypt the data with the generated key. ", "Retry the tahachi");
            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     *
     * @param keyName                          the name of the key to be created
     * @param invalidatedByBiometricEnrollment if {@code false} is passed, the created key will not
     *                                         be invalidated even if a new fingerprint is enrolled.
     *                                         The default value is {@code true}, so passing
     *                                         {@code true} doesn't change the behavior
     *                                         (the key will be invalidated if a new fingerprint is
     *                                         enrolled.). Note that this parameter is only valid if
     *                                         the app works on Android N developer preview.
     */
    public void createKey(String keyName, boolean invalidatedByBiometricEnrollment) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            // This is a workaround to avoid crashes on devices whose API level is < 24
            // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
            // visible on API level +24.
            // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
            // which isn't available yet.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
            }
            mKeyGenerator.init(builder.build());
            mKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new TahachiException(e);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void setBaseURL(String baseURL) {
        this.baseURL = baseURL;
    }

    public String getBaseURL() {
        return baseURL;
    }

    private class LockUnlockButtonClickListener implements View.OnClickListener {

        private boolean lockingLocal;
        Cipher mCipher;
        String mKeyName;

        LockUnlockButtonClickListener(Cipher cipher, String keyName, boolean lockDesktop) {
            mCipher = cipher;
            mKeyName = keyName;
            lockingLocal = lockDesktop;
        }

        @Override
        public void onClick(View view) {
            setLocking(lockingLocal);
            findViewById(R.id.locked_message).setVisibility(View.GONE);

            // Set up the crypto object for later. The object will be authenticated by use
            // of the fingerprint.
            if (initCipher(mCipher, mKeyName)) {

                // Show the fingerprint dialog. The user has the option to use the fingerprint with
                // crypto, or you can fall back to using a server-side verified password.
                FingerprintAuthenticationDialogFragment fragment
                        = new FingerprintAuthenticationDialogFragment();
                fragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                boolean useFingerprintPreference = mSharedPreferences
                        .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                true);
                if (useFingerprintPreference) {
                    fragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                } else {
                    fragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                }
                fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
            } else {
                // This happens if the lock screen has been disabled or or a fingerprint got
                // enrolled. Thus show the dialog to authenticate with their password first
                // and ask the user if they want to authenticate with fingerprints in the
                // future
                FingerprintAuthenticationDialogFragment fragment
                        = new FingerprintAuthenticationDialogFragment();
                fragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                fragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
            }
        }
    }

    public boolean isLocking() {
        return locking;
    }

    public void setLocking(boolean locking) {
        this.locking = locking;
    }

    /**
     * Returns an input stream containing one or more certificate PEM files. This implementation just
     * embeds the PEM files in Java strings; most applications will instead read this from a resource
     * file that gets bundled with the application.
     */
    private InputStream trustedCertificatesInputStream() {
        String jokoDefaultCertificate;
        if (StringUtils.isNotBlank(BuildConfig.JOKO_SSL_CRT)) {
            // Trusted SSL CRTs could be overriden through global gradle.properties
            jokoDefaultCertificate = BuildConfig.JOKO_SSL_CRT;
        } else {
            jokoDefaultCertificate = "" +
                    "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDfTCCAmWgAwIBAgIEfigrDDANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJQ\n" +
                    "WTEQMA4GA1UECBMHQ0FQSVRBTDERMA8GA1UEBxMIQXN1bmNpb24xEzARBgNVBAoT\n" +
                    "ClNvZGVwIFMuQS4xDTALBgNVBAsTBEpva28xFzAVBgNVBAMTDkpva28gRnJhbWV3\n" +
                    "b3JrMB4XDTE5MTIwMTE5MzcwMVoXDTI5MTEyODE5MzcwMVowbzELMAkGA1UEBhMC\n" +
                    "UFkxEDAOBgNVBAgTB0NBUElUQUwxETAPBgNVBAcTCEFzdW5jaW9uMRMwEQYDVQQK\n" +
                    "EwpTb2RlcCBTLkEuMQ0wCwYDVQQLEwRKb2tvMRcwFQYDVQQDEw5Kb2tvIEZyYW1l\n" +
                    "d29yazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJExJ2IjLmEVhtDD\n" +
                    "prROwQEKChBSp32kdjofVDc1eSZ7mtiUfsmex9B0gc1HJL6CIDLAZW/mUjctlDr+\n" +
                    "ZnojhJNcZkdQNfoqnG0u5Djf6Cq8DL0LFu0U9AyxBNW9Job7Q6LkXEDRYRM2XKD0\n" +
                    "/v0o9Fv6CSAg/iwOfHMGJ9GdeYFzWGUiWCnci92W+6sS3LcJ3CLioRIqMC9REUsi\n" +
                    "xE4xz6+zZPbho75qlV/r+kymJDxfFPnpGjql42azN8baXxVOPrCBHDwV9Vp0jDxs\n" +
                    "xppAMpxVE6k2VHonVacjFqA6VTW2lcWzDVBchJIFMN2vh1crSs+AvKBfePCg93m7\n" +
                    "e5eAbCMCAwEAAaMhMB8wHQYDVR0OBBYEFAf2/I5e62Ev2SztKV4uiq9OZ7AtMA0G\n" +
                    "CSqGSIb3DQEBCwUAA4IBAQByYog699iA/ufhGGdEGQGLAowKPPyhzrdxdgx2Kmpd\n" +
                    "MDl7HM+qTcFrXYzDOPgEmL8Ee+0BRZxHr70v2fgQqMRr3uJkCGNOAu9ta7y400M9\n" +
                    "1vOLswGNiLydRAitThkL6z95L0S7/P6xZq/zb2k4NU0p1FgVhstkt7wlDYUNy4Li\n" +
                    "zVjcEhZ3NDsMsy7PDIj/z9+msJ/gzvqDKZMWyELispy5l+AoKNlvL/jFR1N9SOOY\n" +
                    "FPaUY7dwUU/HFNzmYcsDl1HrOubRlmhZZasD7JxZGldrxXb/AF+7aVRO27+1pdwA\n" +
                    "by7PQBhUxSWjrtlw+TRYXNytZy1HHqDd/WOE6mI975/y\n" +
                    "-----END CERTIFICATE-----\n";
        }
        return new ByteArrayInputStream(jokoDefaultCertificate.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns a trust manager that trusts {@code certificates} and none other. HTTPS services whose
     * certificates have not been signed by these certificates will fail with a {@code
     * SSLHandshakeException}.
     *
     * <p>This can be used to replace the host platform's built-in trusted certificates with a custom
     * set. This is useful in development where certificate authority-trusted certificates aren't
     * available. Or in production, to avoid reliance on third-party certificate authorities.
     *
     * <p>See also {@link CertificatePinner}, which can limit trusted certificates while still using
     * the host platform's built-in trust store.
     *
     * <h3>Warning: Customizing Trusted Certificates is Dangerous!</h3>
     *
     * <p>Relying on your own trusted certificates limits your server team's ability to update their
     * TLS certificates. By installing a specific set of trusted certificates, you take on additional
     * operational complexity and limit your ability to migrate between certificate authorities. Do
     * not use custom trusted certificates in production without the blessing of your server's TLS
     * administrator.
     */
    private X509TrustManager trustManagerForCertificates(InputStream in)
            throws GeneralSecurityException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("expected non-empty set of trusted certificates");
        }

        // Put the certificates a key store.
        char[] pazz = "paZZ1919".toCharArray(); // Any password will work.
        KeyStore keyStore = newEmptyKeyStore(pazz);
        int index = 0;
        for (Certificate certificate : certificates) {
            String certificateAlias = Integer.toString(index++);
            keyStore.setCertificateEntry(certificateAlias, certificate);
        }

        // Use it to build an X509 trust manager.
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, pazz);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new IllegalStateException("Unexpected default trust managers:"
                    + Arrays.toString(trustManagers));
        }
        return (X509TrustManager) trustManagers[0];
    }

    private KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream in = null; // By convention, 'null' creates an empty key store.
            keyStore.load(in, password);
            return keyStore;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        validateCredentials();
    }

}
