package com.pkt.sniff;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import com.pkt.sniff.utils.NetworkUtils;
import com.pkt.sniff.utils.Utils;

public class Sniff {
    private PcapNetworkInterface nif;

    public Sniff(PcapNetworkInterface nif) {
        this.nif = nif;
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

    public Packet capturePacket() throws Exception {
        PcapHandle handle = NetworkUtils.createPcapHandle(nif);
        Packet packet = handle.getNextPacketEx();

        handle.close();

        return packet;
    }

    public Packet captureFilteredPacket(String filter) throws Exception {
        PcapHandle handle = NetworkUtils.createPcapHandle(nif);

        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        Packet packet = handle.getNextPacketEx();

        handle.close();

        return packet;
    }

    public Packet capturePacket(String ipAddr) throws Exception {
        PcapHandle handle = NetworkUtils.createPcapHandle(ipAddr);
        Packet packet = handle.getNextPacketEx();

        handle.close();

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

    public IpV4Header getPacketHeaders(Packet packet) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        IpV4Header headers = ipV4Packet.getHeader();

        return headers;

    }

}
