package ca;

/**
 * Author:CHEN_DONG
 * Date:2021/5/29 23:21
 * Description:
 **/
public class MessageHeader {
    String S_mac;
    String S_ip;
    String D_mac;
    String D_ip;
    private int length;
    public MessageHeader(String s_mac,String s_ip,String d_mac,String d_ip,int length){
        this.S_mac=s_mac;
        this.S_ip=s_ip;
        this.D_ip=d_ip;
        this.D_mac=d_mac;
        this.length=length;
    }

    public String getD_ip() {
        return D_ip;
    }

    public String getD_mac() {
        return D_mac;
    }

    public String getS_ip() {
        return S_ip;
    }

    public String getS_mac() {
        return S_mac;
    }

    public int getLength() {
        return length;
    }
}
