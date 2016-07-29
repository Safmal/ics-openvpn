package de.blinkt.openvpn.pkcs11.exception;

/**
 * Created by Malik on 26.07.16.
 */
public class HandleNotFoundException extends Pkcs11CallerException{

    public HandleNotFoundException (String message) {
        super(message);
    }
}
