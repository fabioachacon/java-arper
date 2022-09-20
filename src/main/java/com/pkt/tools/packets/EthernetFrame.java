package com.pkt.tools.packets;

import org.pcap4j.packet.Packet.Builder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

public class EthernetFrame {
    private MacAddress srcMacAddress;
    private MacAddress dstMacAddress;
    private EthernetPacket.Builder etherBuilder;
    private Builder payload;
    private EtherType type;

    public EthernetFrame(MacAddress srcMacAddress, MacAddress dstMacAddress, Builder arp, EtherType type) {
        this.type = type;
        this.payload = arp;
        this.dstMacAddress = dstMacAddress;
        this.srcMacAddress = srcMacAddress;
    }

    public EthernetPacket.Builder getFrame() {
        etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(dstMacAddress)
                .srcAddr(srcMacAddress)
                .type(type)
                .payloadBuilder(payload)
                .paddingAtBuild(true);

        return etherBuilder;
    }

    public MacAddress getSrcMacAddress() {
        return srcMacAddress;
    }

    public void setSrcMacAddress(MacAddress srcMacAddress) {
        this.srcMacAddress = srcMacAddress;
    }

    public MacAddress getDstMacAddress() {
        return dstMacAddress;
    }

    public void setDstMacAddress(MacAddress dstMacAddress) {
        this.dstMacAddress = dstMacAddress;
    }
}
