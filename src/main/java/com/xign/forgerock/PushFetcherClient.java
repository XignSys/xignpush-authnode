/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.xign.forgerock;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xign.xignmanager.common.Crypto;
import com.xign.xignmanager.common.JWTClaims;
import com.xign.xignmanager.common.UserInfoSelector;
import com.xign.forgerock.exception.XignTokenException;
import com.xign.forgerock.util.Util;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author palle
 */
class PushFetcherClient {

    private final String clientId, keyPassword, keyAlias, trustAlias;
    private final URL endpoint;
    private final KeyStore clientKeys, trustStore;
    private final X509Certificate trustCert;
    private final boolean isSSL;
    private static final Logger LOG = Logger.getLogger(PushFetcherClient.class.getName());

    private HttpsURLConnection urlConnection;
    private HttpURLConnection urlConnectionNoSSL;
    private final JsonParser PARSER = new JsonParser();

    PushFetcherClient(InputStream pin, X509Certificate httpsTrust) throws XignTokenException {
        Properties properties = new Properties();
        try {
            properties.load(pin);
        } catch (IOException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("error loading properties");
        }

        String encodedKeystore = properties.getProperty("client.keystore");
        String password = properties.getProperty("client.keystore.password");
        String kAlias = properties.getProperty("client.keystore.alias");
        String pushEndpoint = properties.getProperty("manager.url.token").replace("/token", "/push");
        clientId = properties.getProperty("client.id");
        ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(encodedKeystore.getBytes()));

        try {
            this.clientKeys = KeyStore.getInstance("pkcs12");
        } catch (KeyStoreException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("error loading client keystore");
        }

        this.keyPassword = password;
        try {
            this.keyAlias = kAlias;
            this.clientKeys.load(in, password.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("error constructing requester");
        }

        try {
            this.trustStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
        } catch (KeyStoreException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("error loading trust keystore");
        }

        this.trustAlias = "trust";
        try {
            this.trustStore.load(null, null);
            String encodedSignatureTrustCert = properties.getProperty("client.trustcert");
            in = new ByteArrayInputStream(Base64.getDecoder().decode(encodedSignatureTrustCert.getBytes()));
            CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            this.trustStore.setCertificateEntry(trustAlias, cf.generateCertificate(in));

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("error constructing requester");
        }

        CookieManager cookieManager = new CookieManager();
        CookieHandler.setDefault(cookieManager);

        this.trustCert = httpsTrust;

        try {
            //this.clientId = client_id;
            this.endpoint = new URL(pushEndpoint);
        } catch (MalformedURLException ex) {
            Logger.getLogger(PushFetcherClient.class.getName()).log(Level.SEVERE, null, ex);
            throw new XignTokenException("pushEndpoint " + pushEndpoint + " is not an url");
        }

        this.isSSL = pushEndpoint.contains("https://");

    }

    JWTClaims requestPushWithUsername(String userid, UserInfoSelector uiselector) throws XignTokenException {
        JsonObject resultObject;

        try {
            PrivateKey pkey = (PrivateKey) clientKeys.getKey("xyz", "changeit".toCharArray());

            JsonObject payload = new JsonObject();
            payload.addProperty("userid", userid);
            payload.addProperty("nonce", RandomStringUtils.randomAlphanumeric(16));
            payload.addProperty("version", "2.0");
            if (uiselector != null) {
                payload.add("uiselector", new Gson().toJsonTree(uiselector));
            }

            byte[] signed = Base64.getEncoder().encode(Crypto.sign(payload.toString().getBytes("ISO8859-1"), pkey));
            String signature = new String(signed, "ISO8859-1");

            JsonObject o = new JsonObject();
            o.addProperty("type", 43);
            o.addProperty("client_id", this.clientId);
            o.add("payload", payload);
            o.addProperty("signature", signature);

            String result = sendMessage(o);
            assert result != null;
            resultObject = PARSER.parse(result).getAsJsonObject();

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException
                | IOException | CertificateException | InvalidKeyException
                | InvalidKeySpecException | SignatureException
                | KeyManagementException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new XignTokenException("error requesting push authentication");
        }

        return Util.processTokenResponse(resultObject, clientKeys, keyAlias, keyPassword, trustStore, trustAlias);
    }

    private String sendMessage(JsonObject to) throws CertificateException,
            NoSuchAlgorithmException, KeyStoreException, KeyManagementException,
            IOException {
        try {
            makeConnection();
        } catch (NoSuchProviderException ex) {
            LOG.log(Level.SEVERE, null, ex);
            return null;
        }
        try {
            if (isSSL) {
                OutputStream out = new BufferedOutputStream(urlConnection.getOutputStream());
                out.write(("cmd=" + to.toString()).getBytes());
                out.flush();
                out.close();

                InputStream in = new BufferedInputStream(urlConnection.getInputStream());
                JsonObject resp = readStream(in);
                in.close();
                return resp.toString();
            } else {
                OutputStream out = new BufferedOutputStream(urlConnectionNoSSL.getOutputStream());
                out.write(("cmd=" + to.toString()).getBytes());
                out.flush();
                out.close();

                InputStream in = new BufferedInputStream(urlConnectionNoSSL.getInputStream());
                JsonObject resp = readStream(in);
                in.close();
                return resp.toString();
            }
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "Error in connection to endpoint, returning ...", ex);
            return null;
        }
    }

    private JsonObject readStream(InputStream in) throws IOException {
        JsonParser p = new JsonParser();
        byte[] msgBytes = IOUtils.toByteArray(in);
        return p.parse(new String(msgBytes)).getAsJsonObject();
    }

    private void makeConnection() throws IOException, KeyStoreException, CertificateException,
             NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException {
        if (isSSL) {
            SSLContext sslContext;
            if (trustCert != null) {
                sslContext = Util.getSSLContext(trustCert);
            } else {
                sslContext = Util.getDefaultContext();
            }

            urlConnection = (HttpsURLConnection) endpoint.openConnection();
            urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            urlConnection.setHostnameVerifier(new NullHostnameVerifier());

            urlConnection.setDoOutput(true);
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            urlConnection.setChunkedStreamingMode(0);
        } else {
            urlConnectionNoSSL = (HttpURLConnection) endpoint.openConnection();
            urlConnectionNoSSL.setDoOutput(true);
            urlConnectionNoSSL.setRequestMethod("POST");
            urlConnectionNoSSL.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            urlConnectionNoSSL.setChunkedStreamingMode(0);
        }
    }

    public class NullHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }

    }
}
