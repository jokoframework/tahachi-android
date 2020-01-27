# tahachi-android
Android client for remote desktop lock/unlock using biometrics

Tahachi comes from guarani. It means guardian, soldier.
It is an android client for [tahachi-backend](https://github.com/jokoframework/tahachi-backend). 
The goal is to use Android Biometrics (fingerprint at the moment), to lock or unlock your Linux Desktop. 
Since security is **very important** to handle your desktop access; this app by default uses SSL pinning and SSL connections only.

This is the first public version, so braves only :)

It connects to a REST-API using JWT and self-signed certificate.

##Steps to run

 1. tahachi-backend running

  1.1 **For testing purposes**, app comes with CRT from tahachi-backend default configuration. For production or real case scenarios, you are encouraged to create your own keystore and certificates. 
  
  1.2 In case you created your own keystore, you will need a SSL-Certificate CRT stored in `~.gradle/gradle.properties` -> `joko_ssl_crt`
  
 2. Android 6.0+ (API Level 21 or greater)
 3. Android Smartphone with fingerprint enrolled
 4. SSL pinning. See `xml/network_security_config.xml`
 5. Settings: 
  
    5.1 Valid backend credentials (user/password)
    5.2 Default host or
    5.3 List of hosts can be added/edited manually


## TODO

1. Better graphics and UX
2. Handle edge conditions/errors more gracefully
3. Update to [Android Q Biometrics capabilities](https://source.android.com/security/biometric/)

 * Based on [Android example](https://github.com/googlearchive/android-FingerprintDialog)
 
