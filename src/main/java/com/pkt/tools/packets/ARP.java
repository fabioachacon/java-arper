package com.pkt.tools.packets;

import java.net.InetAddress;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

public class ARP {
    private String srcIpAddress;
    private String dstIpAddress;
    private MacAddress srcMacAddress;
    private MacAddress dstMacAddress;

    public ARP(String srcIpAddres, String dstIpAddress, MacAddress srcMacAddress, MacAddress dstMacAddress) {
        this.srcIpAddress = srcIpAddres;
        this.srcMacAddress = srcMacAddress;
        this.dstIpAddress = dstIpAddress;
        this.dstMacAddress = dstMacAddress;
    }

    public Builder getPacket() {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        try {
            arpBuilder.hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(srcMacAddress)
                    .srcProtocolAddr(InetAddress.getByName(srcIpAddress))
                    .dstHardwareAddr(dstMacAddress)
                    .dstProtocolAddr(InetAddress.getByName(dstIpAddress));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return arpBuilder;
    }

}
