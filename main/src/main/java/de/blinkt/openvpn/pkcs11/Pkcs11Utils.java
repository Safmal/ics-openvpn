/*
 * Copyright (c) 2015, CJSC Aktiv-Soft. See the LICENSE file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

package de.blinkt.openvpn.pkcs11;

import java.io.UnsupportedEncodingException;

public class Pkcs11Utils {
    public static String removeTrailingSpaces(byte[] string) {
        String result = "";
        try {
            result = (new String(string, "UTF-8")).replaceAll(" *$", "");
        } catch (UnsupportedEncodingException e) {
        }
        return result;
    }
}
