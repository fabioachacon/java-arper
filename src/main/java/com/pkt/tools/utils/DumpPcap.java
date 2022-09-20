package com.pkt.tools.utils;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

public class DumpPcap {
    private PcapHandle handle;
    private PcapDumper dumper;

    private static final String PCAP_FILE_KEY = DumpPcap.class.getName() + ".pcapFile";
    private static final String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "dump.pcap");

    public DumpPcap(PcapNetworkInterface nif) {
        handle = NetworkUtils.createPcapHandle(nif);
    }

    public void dump(Packet packet) {
        try {
            dumper = handle.dumpOpen(PCAP_FILE);

            dumper.dump(packet);
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }

    public void close() {
        dumper.close();
    }

}
