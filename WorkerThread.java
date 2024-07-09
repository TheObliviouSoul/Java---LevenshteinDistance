// WorkerThread is responsible for processing individual log entries to detect vulnerabilities
public class WorkerThread extends Thread {
    private final String logEntry; // The log entry this thread will process
    private final int lineNumber; // The line number of the log entry, used for reporting
    private final String vulnerabilityPattern; // The vulnerability pattern to match against the log entry
    private static final int DISTANCE_THRESHOLD = 3; // Threshold for deciding when a substring variation is close enough to the pattern to be considered a match
    private boolean vulnerabilityDetected = false; // Flag to indicate if a vulnerability has been detected in this log entry, to avoid duplicate reporting

    // Constructor for the WorkerThread, assigning the log entry, line number, and vulnerability pattern
    public WorkerThread(String logEntry, int lineNumber, String vulnerabilityPattern) {
        this.logEntry = logEntry;
        this.lineNumber = lineNumber;
        this.vulnerabilityPattern = vulnerabilityPattern;
    }

    // The main execution method for the thread, which searches the log entry for the vulnerability pattern
    @Override
    public void run() {
        // Iterate through the log entry, comparing substrings to the vulnerability pattern
        for (int i = 0; i <= logEntry.length() - vulnerabilityPattern.length() && !vulnerabilityDetected; i++) {
            // Extract a substring from the log entry for comparison
            String toCompare = logEntry.substring(i, i + vulnerabilityPattern.length());
            LevenshteinDistance levenshteinDistance = new LevenshteinDistance();
            // Calculate the Levenshtein distance between the substring and the pattern
            int distance = levenshteinDistance.Calculate(toCompare, vulnerabilityPattern);

            // Check if the distance is within the threshold and if the change is acceptable
            if (distance <= DISTANCE_THRESHOLD && levenshteinDistance.isAcceptable_change()) {
                // Report the vulnerability detection and increment the shared count
                System.out.println("Vulnerability detected at line " + lineNumber + ": " + logEntry);
                MasterThread.incrementVulnerabilityCount();
                // Set the flag to true to indicate that this log entry has a detected vulnerability
                vulnerabilityDetected = true;
            }
        }
    }
}
