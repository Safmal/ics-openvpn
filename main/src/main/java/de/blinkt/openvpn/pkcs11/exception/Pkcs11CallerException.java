/*
 * Copyright (c) 2015, CJSC Aktiv-Soft. See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package de.blinkt.openvpn.pkcs11.exception;

public abstract class Pkcs11CallerException extends Exception {
    public Pkcs11CallerException(String message) {
        super(message);
    }
}
