package de.blinkt.openvpn.pkcs11.exception;

/**
 * Created by Malik on 28.07.16.
 */
public class PinEmptyException extends Exception {

    public PinEmptyException(){
        super("Pin is empty");
    }
}
