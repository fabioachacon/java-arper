package com.pkt.tools.exceptions;

public class HAddrNotFoundException extends Exception {

    public HAddrNotFoundException() {
        super("Couldn't find a MAC Address associeted with this IP");
    }
}
