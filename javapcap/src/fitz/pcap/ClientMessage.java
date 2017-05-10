package fitz.pcap;

import com.eclipsesource.json.JsonObject;
import fitz.pcap.dto.Flow;
import fitz.pcap.util.TimeSlotTuple;
import fitz.pcap.util.WebSocketFlowServer;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;

/**
 * Created by FitzRoi on 5/1/17.
 */
public class ClientMessage {
    private Flow flow;
    private WebSocketFlowServer socket;
    private ArrayList<Integer> ports = new ArrayList<>(Arrays.asList(80, 8080, 443));
    private ArrayList<String> hostIps;
    private ArrayList<TimeSlotTuple> timeSlots;
    private String msg = null;


    public ClientMessage(WebSocketFlowServer socket,
                         Flow flow,
                         ArrayList<String> hostIps,
                         ArrayList<TimeSlotTuple> timeSlots){
        this.socket = socket;
        this.flow = flow;
        this.hostIps = hostIps;
        this.timeSlots = timeSlots;
    }

    public void send() {
        if(msg != null)
            socket.sendMessage(msg);
    }

    /**
     * compose a message in json format and convert to string
     * to be sent to client
     */
    public void createMessage() {
        JsonObject toSocket = new JsonObject();

        if (flow != null) {
            String date = flow.getTime();
            java.util.Date tempDate = null;
            Calendar cal = Calendar.getInstance();
            int hr = 0, min = 0;

            try {
                tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSSSS").parse(date);
                cal.setTime(tempDate);
            } catch (ParseException e) {
                e.printStackTrace();
            }

            if(tempDate != null) {
                hr = cal.get(Calendar.HOUR);
                min = cal.get(Calendar.MINUTE);
            }

            toSocket.add("hostIndex", getHostIndex(flow.getSrcip().replace("/", "")));
            toSocket.add("portIndex", getPortIndex(flow.getDstport()));
            toSocket.add("timeSlotIndex", getTimeslotIndex(hr, min));
            toSocket.add("bytes", flow.getBytes());
            msg = toSocket.toString();
        }
    }


    public int getTimeslotIndex(int hr, int min)
    {
        int SlotIndex = 0;
        for (int i= 0; i < timeSlots.size();i++)
        {
            if (hr == timeSlots.get(i).getHour() && min > timeSlots.get(i).getStartMin() && min < timeSlots.get(i).getEndMin())
            {
                SlotIndex = i;

            }
        }
        return SlotIndex;
    }


    public int getHostIndex(String hostIp){
        return hostIps.indexOf(hostIp);
    }


    public int getPortIndex(int port){
        int index = ports.indexOf(port);
        return (index == -1 ? 0 : index );
    }

}
