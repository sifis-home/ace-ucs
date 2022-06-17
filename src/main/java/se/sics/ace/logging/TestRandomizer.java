package se.sics.ace.logging;


import java.io.*;
import java.util.Random;

public class TestRandomizer {

public TestRandomizer(String fileName, int length) {
    try {
        String randomString = getRandomHexString(length);

        FileWriter writer = new FileWriter(fileName);
        writer.write(randomString);
        writer.close();
        System.out.println("Successfully wrote to the 'random.txt' file. " +
                "Random string: " + randomString);
    } catch (IOException e) {
        System.out.println("An error occurred.");
        e.printStackTrace();
    }
}

    private String getRandomHexString(int numChars){
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while(sb.length() < numChars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.substring(0, numChars);
    }

}
