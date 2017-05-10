package fitz.pcap.util;

/**
 * Created by FitzRoi on 5/1/17.
 */
public class TimeSlotTuple {
    private String timeSlotID;
    private int hour;
    private int startMin;
    private int endMin;

    public TimeSlotTuple(String timeSlotID, int hour, int startMin, int endMin){
        this.timeSlotID = timeSlotID;
        this.hour = hour;
        this.startMin = startMin;
        this.endMin = endMin;
    }


    public String getTimeSlotID() {
        return timeSlotID;
    }

    public void setTimeSlotID(String timeSlotID) {
        this.timeSlotID = timeSlotID;
    }

    public int getHour() {
        return hour;
    }

    public void setHour(int hour) {
        this.hour = hour;
    }

    public int getStartMin() {
        return startMin;
    }

    public void setStartMin(int startMin) {
        this.startMin = startMin;
    }

    public int getEndMin() {
        return endMin;
    }

    public void setEndMin(int endMin) {
        this.endMin = endMin;
    }
}
