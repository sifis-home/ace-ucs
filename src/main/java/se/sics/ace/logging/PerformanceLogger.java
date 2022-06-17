package se.sics.ace.logging;

import java.io.IOException;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.*;

public class PerformanceLogger {

    private static PerformanceLogger singleton = null;

    private static Logger LOGGER;

    private PerformanceLogger(String fileName, String randomizer) {
        LOGGER = Logger.getLogger(PerformanceLogger.class.getName());

        FileHandler handler = null;
        try {
            handler =  new FileHandler(fileName, true);
            handler.setLevel(Level.INFO);
            handler.setFormatter(new SimpleFormatter() {
                private final String format = "[%1$tF %1$tT] [%2$-7s] [" + randomizer + "]  %3$s %n";

                @Override
                public synchronized String format(LogRecord lr) {
                    return String.format(format,
                            new Date(lr.getMillis()),
                            lr.getLevel().getLocalizedName(),
                            lr.getMessage()
                    );
                }
            });
        } catch (IOException e) {
            System.out.println(PerformanceLogger.class.getName() + ": Unable to write to log file");
        }
        LOGGER.addHandler(handler);
        assert handler != null;
        LOGGER.setUseParentHandlers(false);

    }

    public static PerformanceLogger getInstance() throws AssertionError {
        if (singleton == null){
            throw new AssertionError("You have to call init first");
        }
        return singleton;
    }

    public synchronized static PerformanceLogger init(String fileName, String randomizer) {
        if (singleton != null) {
            throw new AssertionError("You already initialized me");
        }

        singleton = new PerformanceLogger(fileName, randomizer);
        return singleton;
    }

    public Logger getLogger() {
        return LOGGER;
    }
}
