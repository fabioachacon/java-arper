package com.pkt;

import com.pkt.sniff.Arper;

public class App {

    public static void main(String[] args) {
        final String TARGET_IP = "";
        final String GATEWAY_IP = "";

        Arper arper = new Arper(TARGET_IP, GATEWAY_IP);
        arper.run();

    }

}
