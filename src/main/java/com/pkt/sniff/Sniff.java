package com.pkt.sniff;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.Packet;
import com.pkt.sniff.utils.NetworkUtils;
import com.pkt.sniff.utils.Utils;

public class Sniff {
    private PcapNetworkInterface nif;
    private PcapHandle handle;

    public Sniff(PcapNetworkInterface nif) {
        try {
            handle = NetworkUtils.createPcapHandle(nif);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {

        while (true) {
            System.out.println("Sniffing...\n");

            try {
                Packet packet = capturePacket();
                if (packet != null) {
                    System.out.println("--------------------------------------\n");
                    System.out.println(packet);
                } else {
                    System.out.println("No packet was captured.\n");
                    System.out.println("Retrying...");
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            Utils.sleep(3000);
        }

    }

    public void setFilter(String filter) {
        try {
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }

    public Packet capturePacket() throws Exception {
        Packet packet = handle.getNextPacketEx();

        return packet;
    }

    public void capturePackets(int count) {
        try {
            final PcapHandle handle = NetworkUtils.createPcapHandle(nif);
            final ExecutorService pool = Executors.newCachedThreadPool();
            final PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(PcapPacket packet) {
                    System.out.println(handle.getTimestampPrecision());
                    System.out.println(packet);
                }
            };

            try {
                handle.loop(count, listener, pool);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                pool.shutdown();
                handle.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void closeHandle() {
        handle.close();
    }

}
