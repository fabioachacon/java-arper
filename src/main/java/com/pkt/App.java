package com.pkt;

import com.pkt.tools.Arper;

public class App {

    public static void main(String[] args) {
        final String TARGET_IP = args[0];
        final String GATEWAY_IP = args[1];

        Arper arper = new Arper(TARGET_IP, GATEWAY_IP);
        arper.run(100);
    }

}
