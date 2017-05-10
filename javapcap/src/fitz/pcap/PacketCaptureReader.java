package fitz.pcap;

import fitz.pcap.dto.Flow;
import fitz.pcap.dto.Packet;
import fitz.pcap.util.TimeSlotTuple;
import fitz.pcap.util.WebSocketFlowServer;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

/**
 * Created by FitzRoi on 5/1/17.
 */

    /**
     * The Class PacketCaptureReader.
     */
    public class PacketCaptureReader implements Runnable{

        private BufferedReader _reader = null;
        private File pcapFile;
        private WebSocketFlowServer socket;
        private HashMap<String, String> ipMaps;
        private ArrayList<String> hostIPs = new ArrayList<>();
        private ArrayList<TimeSlotTuple> timeSlots = new ArrayList<>();


        public PacketCaptureReader( File pcapFile, WebSocketFlowServer socket) {
            this.pcapFile = pcapFile;
            this.socket = socket;
            this.ipMaps = new HashMap<>();
        }

//        public void run(){
//            try{
//                String cmd = "tcpdump -r " + pcapFile.getAbsolutePath() + " -n " + " -tttt -v ip";
//                String line;
//                int lineCount =0;
//                long initTime = System.currentTimeMillis();
//                String tcpDumpResult = runTCPDump(cmd, true);
//
//                while (tcpDumpResult != null){
//                    System.out.println(tcpDumpResult);
//                    Packet packet = Packet.parse(tcpDumpResult);
////                    Flow flow = packetToFlow(packet);
//                      ClientMessage msg = new ClientMessage(socket, packet);
//                    System.out.println(packet.toString());
//                    msg.send();
//                    tcpDumpResult = runTCPDump(cmd, true);
//                    lineCount++;
//                }
//            }catch(Exception e){
//                e.printStackTrace();
//            }
//        }


        public void run(){
            try{
                String[] cmd = { "tcpdump", "-r", pcapFile.getAbsolutePath(), "-n", "-tttt", "-v", "ip" };
//                String[] cmd = { "tcpdump", "-n","tcp" , "dst", "portrange", "1-1023" };
                Process p = Runtime.getRuntime().exec( cmd );
                String dstIp;
                int ipIndex;
                int lineCount = 0;
                int skips = 10;
                createTimeslots();

                _reader = new BufferedReader( new InputStreamReader( p.getInputStream(), "US-ASCII" ) );
                String line;
                long initTime = System.currentTimeMillis();
                while ((line = _reader.readLine()) != null){
                    Packet packet = Packet.parse(line + _reader.readLine());
                    Flow flow = packetToFlow(packet);

                    //use the first 6 ip addresses as host IPs
                    if(lineCount <= 6){
                        if(flow != null)
                            hostIPs.add(flow.getDstip());
                    }

                    //compose a message to send to client for all other flows
                    if(lineCount > 6 && (lineCount % skips)== 0){
                        if(flow != null ) {
                            dstIp = flow.getSrcip().replace("/", "");
                            ipIndex = hostIPs.indexOf(dstIp);
                            //skip flows for ips that do not match a host
                            if(ipIndex != -1) {
                                ClientMessage msg = new ClientMessage(socket, flow, hostIPs, timeSlots);
                                msg.createMessage();
                                msg.send();
                            }
                        }
                    }

                    lineCount++;

                }
            }catch(Exception e){
                e.printStackTrace();
            }
        }


        public String runTCPDump(String cmd, boolean waitForResult){
            String tcpdumpCmdResponse = null;
            ProcessBuilder pcapProcessBuilder = null;
            String operatingSystem = System.getProperty("os.name");

            if (operatingSystem.toLowerCase().contains("window")) {
                // In case of windows run command using "crunchifyCmd"
                pcapProcessBuilder = new ProcessBuilder("cmd", "/c", cmd);
            } else {
                // In case of Linux/Ubuntu run command using /bin/bash
                pcapProcessBuilder = new ProcessBuilder("/bin/bash", "-c", cmd);
            }

            pcapProcessBuilder.redirectErrorStream(true);
            try {
                Process process = pcapProcessBuilder.start();
                if (waitForResult) {
                    InputStream crunchifyStream = process.getInputStream();
                    tcpdumpCmdResponse = getStringFromStream(crunchifyStream);
                    crunchifyStream.close();
                }

            } catch (Exception e) {
                System.out.println("Error Executing tcpdump command" + e);
            }
            return tcpdumpCmdResponse;
        }


        private static String getStringFromStream(InputStream stream) throws IOException {
            System.out.println("inside getStringFromStream()");
            if (stream != null) {
                Writer crunchifyWriter = new StringWriter();

                char[] crunchifyBuffer = new char[2048];
                try {
                    Reader reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"));
                    int count;
                    while ((count = reader.read(crunchifyBuffer)) != -1) {
                        crunchifyWriter.write(crunchifyBuffer, 0, count);
                    }
                } finally {
                    stream.close();
                }
                return crunchifyWriter.toString();
            } else {
                return "";
            }
        }


        private Flow packetToFlow(Packet packet) throws IOException {
            if(packet == null){
                return null;
            }
            Flow flow = new Flow();
            flow.setDate(packet.getTimeStr());
            flow.setTime(packet.getTimeStr());
            flow.setSrcip(packet.getSrc().toString().replace("/",""));
            flow.setDstip(packet.getDst().toString().replace("/",""));
            flow.setProtocol(packet.getProtocol());
            flow.setBytes(packet.getLength());
            flow.setPackets(packet.getPackets());

            if(packet.getDstPort() != null){
                flow.setDstport(Integer.parseInt(packet.getDstPort()));
            }else{
                flow.setDstport(0);
            }

            if(packet.getSrcPort() != null){
                flow.setSrcport(Integer.parseInt(packet.getSrcPort()));
            }else{
                flow.setSrcport(0);
            }
            return flow;
        }




        private String refreshMappedIP(String ipAddress){
            String randomIP = generateRandomIP();
            this.ipMaps.put(ipAddress, randomIP);
            return randomIP;
        }

        private String getMappedIPAddress(String ipAddress){
            if(this.ipMaps.containsKey(ipAddress)){
                return this.ipMaps.get(ipAddress);
            }else{
                String randomIP = generateRandomIP();
                this.ipMaps.put(ipAddress, randomIP);
                return randomIP;
            }
        }

        private String generateRandomIP(){
            Random r = new Random();
            String ip = r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256);
            if(isUnique(ip)){
                return ip;
            }else{
                return generateRandomIP();
            }
        }

        private boolean isUnique(String ip){
            HashMap<String, String> map = ipMaps;
            ArrayList<String> values = new ArrayList<>(map.values());
            if(values.contains(ip)){
                return false;
            }else{
                return true;
            }
        }

        private void createTimeslots()
        {
            //string Starttime = "";
            int count = 0;
            for (int j = 0; j < 24; j++)
            {
                for (int i = 0; i <= 55; i = i + 5)
                {
                    int k = i;

                    timeSlots.add(new TimeSlotTuple("T" + (count + 1), j, i, i + 5));
                    count = count + 1;
                }
            }

        }
    }
