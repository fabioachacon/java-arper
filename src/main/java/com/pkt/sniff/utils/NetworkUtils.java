package com.pkt.sniff.utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

public class NetworkUtils {
    private static final int SNAP_LEN = 65536;
    private static final int TIMEOUT = 10;

    public static PcapHandle createPcapHandle(PcapNetworkInterface nif) {
        try {
            return nif.openLive(SNAP_LEN, PromiscuousMode.PROMISCUOUS, TIMEOUT);
        } catch (PcapNativeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PcapHandle createPcapHandle(String ipAddr) throws Exception {
        PcapNetworkInterface nif = findNetWorkInterface(ipAddr);
        PcapHandle handle = nif.openLive(SNAP_LEN, PromiscuousMode.PROMISCUOUS, TIMEOUT);

        return handle;
    }

    public static PcapNetworkInterface selectNetWorkInterface() {
        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();

            return nif;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PcapNetworkInterface findNetWorkInterface(String ipAddr)
            throws PcapNativeException, UnknownHostException {
        InetAddress addr = InetAddress.getByName(ipAddr);
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

        return nif;
    }

}
