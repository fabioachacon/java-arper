package com.pkt;

import org.pcap4j.util.MacAddress;
import com.pkt.sniff.Arper;

public class App {

    public static void main(String[] args) {
        final MacAddress SRC_MAC = MacAddress.getByName("");
        final String SRC_IP = "";
        final String TARGET_IP = "";
        final String GATEWAY_IP = "";

        Arper arper = new Arper(SRC_IP, SRC_MAC, TARGET_IP, GATEWAY_IP);
        arper.run();

    }

}
