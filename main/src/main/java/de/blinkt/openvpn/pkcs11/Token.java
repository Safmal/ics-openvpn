/*
 * Copyright (c) 2015, CJSC Aktiv-Soft. See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package de.blinkt.openvpn.pkcs11;

import android.util.Base64;
import android.util.Log;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;


import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.jce.provider.X509CertificateObject;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import de.blinkt.openvpn.core.VpnStatus;
import de.blinkt.openvpn.pkcs11.exception.HandleNotFoundException;
import de.blinkt.openvpn.pkcs11.exception.KeyNotFoundException;
import de.blinkt.openvpn.pkcs11.exception.Pkcs11CallerException;
import de.blinkt.openvpn.pkcs11.exception.Pkcs11Exception;

//import sun.security.pkcs11.SunPKCS11;

public class Token implements Serializable, Cloneable {

    private NativeLong mId;

    private NativeLong mSession;


    private String mCertificate = "";
    private X509Certificate mX509Certificate;
    private byte[] mKeyPairId;


    public String getCertificate() {
        return mCertificate;
    }

    public Token(NativeLong slotId, String certId) throws Pkcs11CallerException {
        RtPkcs11 pkcs11 = RtPkcs11Library.getInstance();
        synchronized (pkcs11) {
            mId = slotId;
            //initTokenInfo();
            mKeyPairId = getCKA_ID(certId);

            VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "1) Opening session with token");
            NativeLongByReference session = new NativeLongByReference();
            NativeLong rv = RtPkcs11Library.getInstance().C_OpenSession(mId,
                    Pkcs11Constants.CKF_SERIAL_SESSION, null, null, session);

            if (!rv.equals(Pkcs11Constants.CKR_OK))
                throw Pkcs11Exception.exceptionWithCode(rv);
            mSession = session.getValue();
            VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "Session " + mSession.intValue() + " opened");
            Log.d("PKCS11", "session " + mSession.intValue() + " opened");

            try {
                getCertificateById(pkcs11, mKeyPairId);
                //initCertificatesList(pkcs11, certId);
            } catch (Pkcs11CallerException exception) {
                try {
                    close();
                } catch (Pkcs11CallerException exception2) {
                }
                throw exception;
            }
        }
    }

    public void close() throws Pkcs11Exception {
        NativeLong rv = RtPkcs11Library.getInstance().C_CloseSession(mSession);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);
        mSession = null;
    }

    public void getCertificateById(RtPkcs11 pkcs11, byte[] keyPairId) throws Pkcs11CallerException {

        VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "2) Finding the certificate by its id");
        CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        NativeLongByReference certClass = new NativeLongByReference(Pkcs11Constants.CKO_CERTIFICATE);
        template[0].type = Pkcs11Constants.CKA_CLASS;
        template[0].pValue = certClass.getPointer();
        template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

        ByteBuffer idBuffer = ByteBuffer.allocateDirect(keyPairId.length);
        idBuffer.put(keyPairId);
        template[1].type = Pkcs11Constants.CKA_ID;
        template[1].pValue = Native.getDirectBufferPointer(idBuffer);
        template[1].ulValueLen = new NativeLong(keyPairId.length);

        //byte[] certArray = template[1].getPointer().getByteArray(0, template[1].ulValueLen.intValue());

        NativeLong rv = pkcs11.C_FindObjectsInit(mSession, template, new NativeLong(template.length));
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

        NativeLong[] objects = new NativeLong[1];
        NativeLongByReference count = new NativeLongByReference(new NativeLong(objects.length));

        rv = pkcs11.C_FindObjects(mSession, objects, new NativeLong(objects.length), count);
        NativeLong rv2 = pkcs11.C_FindObjectsFinal(mSession);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);
        else if (!rv2.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv2);
        if (count.getValue().intValue() <= 0)
            throw new KeyNotFoundException();


        CK_ATTRIBUTE[] attributes = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(1);
        attributes[0].type = Pkcs11Constants.CKA_VALUE;

        rv = pkcs11.C_GetAttributeValue(mSession, objects[0], attributes, new NativeLong(attributes.length));
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

        attributes[0].pValue = new Memory(attributes[0].ulValueLen.intValue());

        rv = pkcs11.C_GetAttributeValue(mSession, objects[0], attributes, new NativeLong(attributes.length));
        if (!rv.equals(Pkcs11Constants.CKR_OK)) {
            throw Pkcs11Exception.exceptionWithCode(rv);
        }

        byte[] certificateByteArray = attributes[0].pValue.getByteArray(0, attributes[0].ulValueLen.intValue());
        VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "Certificate object found");

        try {
            VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "3) Parsing the certificate and making PEM String");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(certificateByteArray);
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
            mX509Certificate = certificate;

            StringWriter writer = new StringWriter();
            PemWriter pw = new PemWriter(writer);
            pw.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
            pw.close();

            mCertificate = writer.toString();
            VpnStatus.logMessageOpenVPN(VpnStatus.LogLevel.INFO, 4, "Parsing done");

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String signData(final byte[] data, String tokenPin) throws Pkcs11CallerException {

        RtPkcs11 pkcs11 = RtPkcs11Library.getInstance();
        login(tokenPin);
        NativeLong privateKeyHandle = getPrivateKeyHandle(pkcs11, mKeyPairId);
        if (privateKeyHandle == null) {
            throw new HandleNotFoundException("Private key handle not found!");
        }

        NativeLongByReference count = new NativeLongByReference(new NativeLong());

        ByteBuffer oidBuffer = ByteBuffer.allocateDirect(data.length);
        oidBuffer.put(data);
        CK_MECHANISM mechanism = new CK_MECHANISM(Pkcs11Constants.CKM_RSA_PKCS,
                Native.getDirectBufferPointer(oidBuffer), new NativeLong(data.length));

        NativeLong rv = pkcs11.C_SignInit(mSession, mechanism, privateKeyHandle);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

        rv = pkcs11.C_Sign(mSession, data, new NativeLong(data.length), null, count);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

        byte signature[] = new byte[count.getValue().intValue()];
        rv = pkcs11.C_Sign(mSession, data, new NativeLong(data.length), signature, count);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);
        logout();

        String encodedSignature = Base64.encodeToString(signature, Base64.NO_WRAP);
        return encodedSignature;
    }

    private NativeLong getPrivateKeyHandle(RtPkcs11 pkcs11, byte[] keyPairId) throws Pkcs11CallerException {

        CK_ATTRIBUTE[] template = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);

        final NativeLongByReference keyClass = new NativeLongByReference(Pkcs11Constants.CKO_PRIVATE_KEY);
        template[0].type = Pkcs11Constants.CKA_CLASS;
        template[0].pValue = keyClass.getPointer();
        template[0].ulValueLen = new NativeLong(NativeLong.SIZE);

        ByteBuffer idBuffer = ByteBuffer.allocateDirect(keyPairId.length);
        idBuffer.put(keyPairId);
        template[1].type = Pkcs11Constants.CKA_ID;
        template[1].pValue = Native.getDirectBufferPointer(idBuffer);
        template[1].ulValueLen = new NativeLong(keyPairId.length);

        NativeLong rv = pkcs11.C_FindObjectsInit(mSession, template, new NativeLong(template.length));
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

        NativeLong objects[] = new NativeLong[1];
        NativeLongByReference count = new NativeLongByReference(new NativeLong(objects.length));

        rv = pkcs11.C_FindObjects(mSession, objects, new NativeLong(objects.length), count);
        NativeLong rv2 = pkcs11.C_FindObjectsFinal(mSession);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);
        else if (!rv2.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv2);
        if (count.getValue().intValue() <= 0)
            return null;

        return objects[0];
    }

    public void login(final String pin) throws Pkcs11CallerException {


        NativeLong rv = RtPkcs11Library.getInstance()
                .C_Login(mSession, Pkcs11Constants.CKU_USER, pin.getBytes(), new NativeLong(pin.length()));
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

    }

    public void logout() throws Pkcs11CallerException {

        NativeLong rv = RtPkcs11Library.getInstance().C_Logout(mSession);
        if (!rv.equals(Pkcs11Constants.CKR_OK))
            throw Pkcs11Exception.exceptionWithCode(rv);

    }

    private byte[] getCKA_ID(String certificateId) {

        String id = certificateId.substring(certificateId.lastIndexOf("/") + 1);
        int countBytes = id.length() / 2;
        byte[] data = new byte[countBytes];

        for (int i = 0; i < id.length(); i+= 2) {
            data[i / 2] = (byte) ((Character.digit(id.charAt(i), 16) << 4)
                    + Character.digit(id.charAt(i + 1), 16));
        }

        return data;
    }

    public NativeLong getSession (){
        return mSession;
    }
}
