package se.sics.ace.performance;

import picocli.CommandLine;
import se.sics.ace.logging.PerformanceLogger;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;
import java.util.logging.Level;

public class Utils {

    public static String validateUri(String srvUri, CommandLine.Model.CommandSpec spec)
            throws CommandLine.ParameterException {

        try {
            if (!srvUri.contains("://")) {
                srvUri = "coap://" + srvUri;
            }
            URI uri = new URI(srvUri);
            if (uri.getHost() == null || uri.getPort() == -1) {
                throw new URISyntaxException(uri.toString(),
                        "URI must have host and port parts");
            }
            return uri.toString();
        } catch (URISyntaxException ex) {
            // validation failed
            throw new CommandLine.ParameterException(spec.commandLine(),
                    String.format("Server address not valid:\n > '%s'\n", srvUri));
        }
    }

    public static int validatePort(String portStr, CommandLine.Model.CommandSpec spec)
            throws CommandLine.ParameterException {
        int port = Integer.parseInt(portStr);
        if (port < 1 || port > 65535) {
            throw new CommandLine.ParameterException(spec.commandLine(),
                    String.format("Port number not valid:\n > '%s'\n", port));
        }
        return port;
    }

    public static byte[] hexStringToByteArray(String str, CommandLine.Model.CommandSpec spec)
            throws CommandLine.ParameterException {

        String s = str.replace("0x", "");
        try {
            Integer.parseInt(s, 16);
        }
        catch(NumberFormatException nfe)
        {
            throw new CommandLine.ParameterException(spec.commandLine(),
                    String.format("Hexadecimal value is not valid:\n > '%s'", str));
        }

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String readRandomFile(String pathName) {
        String data = null;
        try {
            File myObj = new File(pathName);
            Scanner reader = new Scanner(myObj);
            // while (reader.hasNextLine()) {
            data = reader.nextLine();
            //     System.out.println(data);
            //}
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        return data;
    }

    public static void initPerformanceLogger (Level level, String logFilePath, String randomFilePath, String cliArgs) {
        String randomizer = readRandomFile(randomFilePath);
        PerformanceLogger.init(logFilePath, randomizer, level);

        PerformanceLogger.getInstance().getLogger().log(Level.INFO,
                "\n\n\n----------------------------" +
                        "\n\nNEW TEST: " + randomizer + "\n");
        PerformanceLogger.getInstance().getLogger().log(Level.INFO,
                "CLI arguments: " + cliArgs + "\n");
    }
}
