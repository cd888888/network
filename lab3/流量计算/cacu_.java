package ca;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

/**
 * Author:CHEN_DONG
 * Date:2021/5/29 23:12
 * Description:
 **/
public class cacu_ {

    public static void main(String[] arg) throws FileNotFoundException {
        String path = System.getProperty("user.dir") + "/src/ca/1.txt";
        File file = new File(path);
        if (!file.exists()) {
            System.err.println("文件不存在");
            return;
        }

        HashMap<String, Integer> d_ip = new HashMap<>();
        HashMap<String, Integer> d_mac = new HashMap<>();
        HashMap<String, Integer> s_mac = new HashMap<>();
        HashMap<String, Integer> s_ip = new HashMap<>();
        int len=0;
        Scanner scanner = new Scanner(file);
        while (scanner.hasNextLine()) {
            String lines = scanner.nextLine();
            String line[] = lines.split(",");
            MessageHeader messageHeader = new MessageHeader(line[1], line[2], line[3], line[4], Integer.parseInt(line[5]));

            caculate( d_ip,messageHeader.getD_ip(),messageHeader.getLength());
            caculate( s_ip,messageHeader.getS_ip(),messageHeader.getLength());
            caculate( d_mac,messageHeader.getD_mac(),messageHeader.getLength());
            caculate( s_mac,messageHeader.getS_mac(),messageHeader.getLength());
            len+=messageHeader.getLength();
        }

        System.out.printf("总流量%d\n",len);
        System.out.println("源mac地址流量");
       List<Map.Entry<String,Integer>> list1=new ArrayList<Map.Entry<String,Integer>>(s_mac.entrySet());
        for (Map.Entry<String, Integer> mapping : list1) {
            System.out.println(mapping.getKey() + ": " + (mapping.getValue()));
        }
        System.out.println("\n源ip地址流量");
        List<Map.Entry<String,Integer>> list2=new ArrayList<Map.Entry<String,Integer>>(s_ip.entrySet());
        for (Map.Entry<String, Integer> mapping : list2) {
            System.out.println(mapping.getKey() + ": " +  (mapping.getValue()));
        }
        System.out.println("\n目的mac地址流量");
        List<Map.Entry<String,Integer>> list3=new ArrayList<Map.Entry<String,Integer>>(d_mac.entrySet());
        for (Map.Entry<String, Integer> mapping : list3) {
            System.out.println(mapping.getKey() + ": " + (mapping.getValue()));
        }
        System.out.println("\n目的ip地址流量");
        List<Map.Entry<String,Integer>> list4=new ArrayList<Map.Entry<String,Integer>>(d_ip.entrySet());
        for (Map.Entry<String, Integer> mapping : list4) {
            System.out.println(mapping.getKey() + ": " + (mapping.getValue()));
        }

    }

    public static void caculate(HashMap<String, Integer> map, String header, int lenth) {
        Set<String> set = map.keySet();
        if (set.contains(header)) {
            Integer nu = map.get(header);
            nu += lenth;
            map.put(header, nu);
        } else {
            map.put(header, lenth);
        }
    }
}
