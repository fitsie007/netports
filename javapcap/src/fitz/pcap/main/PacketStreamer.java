package fitz.pcap.main;

import fitz.pcap.util.WebSocketFlowServer;

import java.io.File;

/**
 * Created by FitzRoi on 5/1/17.
 */
public class PacketStreamer {


    public static void main(String[] args) throws Exception {
        WebSocketFlowServer webSocketFlowServer = new WebSocketFlowServer(8887, new File("./data/daytwo500"));
//        WebSocketFlowServer webSocketFlowServer = new WebSocketFlowServer(8887, new File("./data/balaji_sample_capture.pcap"));

        webSocketFlowServer.start();
    }
}
