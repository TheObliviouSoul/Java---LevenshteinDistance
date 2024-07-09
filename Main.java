import java.util.logging.Logger;
import java.util.logging.Level;

public class Main {
    private static final Logger LOGGER = Logger.getLogger(MasterThread.class.getName()); // Logger for logging important messages and exceptions

    public static void main(String[] args) {
        // The file path for the log file that will be analyzed
        String logFilePath = "D:/ConU/YEAR 3/Winter 2024/COEN 346/Programming Assignment1/COEN 346. PA1/DataSet/vm_1.txt";
        // The vulnerability pattern the program will search for within the log file
        String vulnerabilityPattern = "V04K4B63CL5BK0B";

        // Instantiation of the MasterThread which will manage worker threads for processing the log file
        MasterThread masterThread = new MasterThread(logFilePath, vulnerabilityPattern);

        // Starting the MasterThread's execution
        masterThread.start();

        try {
            // Wait for the MasterThread to finish processing before continuing with the main thread
            masterThread.join();
        } catch (InterruptedException e) {
            // Log any interruptions that occur during the MasterThread's execution
            LOGGER.log(Level.SEVERE, "An exception occurred", e);
        }

        // Indicate that the log analysis is complete after the MasterThread has finished
        System.out.println("Log analysis complete.");
    }
}
