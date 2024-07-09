import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.logging.Level;

// MasterThread oversees the initiation and management of worker threads for processing log entries
public class MasterThread extends Thread {
    private static final Logger LOGGER = Logger.getLogger(MasterThread.class.getName()); // Logger for logging important messages and exceptions
    private final String logFilePath; // The file path for the log file that will be analyzed
    private int worker_number = 2; // Static counter for the number of detected vulnerabilities across all worker threads
    private static int vulnerabilityCount = 0; // Number of detected vulnerabilities
    private double avg = 0; // Initial average number of detected vulnerabilities
    private double approximate_avg = 0; // Average number of detected vulnerabilities (vulnerabilityCount/number of lines in the file)
    private String vulnerabilityPattern; // The pattern to search for

    // Constructor to set the file path for log entries and the vulnerability pattern
    public MasterThread(String logFilePath, String vulnerabilityPattern) {
        this.logFilePath = logFilePath;
        this.vulnerabilityPattern = vulnerabilityPattern;
    }

    // Synchronized method to safely increment the count of detected vulnerabilities
    public static synchronized void incrementVulnerabilityCount() {
        vulnerabilityCount++;
    }

    // The main execution method for the MasterThread
    @Override
    public void run() {
        try {
            // Reading the log file and storing each line as a separate entry
            BufferedReader reader = new BufferedReader(new FileReader(logFilePath));
            List<String> logEntries = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                logEntries.add(line);
            }
            reader.close();

            // Index to keep track of which log entries have been processed
            int startIndex = 0;
            // Continuously process log entries until all have been checked
            while (startIndex < logEntries.size()) {
                // ExecutorService manages a fixed pool of worker threads
                ExecutorService workerThreadPool = Executors.newFixedThreadPool(worker_number);
                // Determine the end index for processing in this iteration
                int endIndex = Math.min(startIndex + worker_number, logEntries.size());

                // Assign each log entry to a WorkerThread for processing
                for (int i = startIndex; i < endIndex; i++) {
                    WorkerThread worker = new WorkerThread(logEntries.get(i), i + 1, vulnerabilityPattern);
                    workerThreadPool.execute(worker);
                }

                // Await the completion of all worker threads in the pool
                workerThreadPool.shutdown();
                workerThreadPool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);

                // Calculate the new average based on the updated vulnerability count
                approximate_avg = (double) vulnerabilityCount / logEntries.size();
                // If the new average is 20% higher, adjust the number of worker threads
                if (approximate_avg >= avg * 1.2) {
                    Thread.sleep(2000); // Sleep for transition tracking
                    avg = approximate_avg; // Update avg with the new value
                    worker_number += 2; // Increase worker threads by 2 for the next round
                }

                // Prepare for the next set of log entries to process
                startIndex += worker_number;
            }

            System.out.println("All worker threads have completed their tasks.");
            System.out.println("Final number of worker threads: " + worker_number);
            System.out.println("Total number of vulnerabilities detected: " + vulnerabilityCount);
        } catch (IOException | InterruptedException e) {
            // Log any exceptions that occur during the thread execution
            LOGGER.log(Level.SEVERE, "An exception occurred", e);
        }
    }
}
