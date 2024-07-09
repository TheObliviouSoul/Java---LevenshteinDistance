**Objective:**
- Develop a multi-threaded Java application to detect vulnerabilities in log files.

**Components:**
1. **MasterThread:**
   - Controls the process, reads the log file, and delegates tasks to WorkerThreads.
   - Manages attributes like `vulnerabilityPattern`, `worker_number`, and `vulnerabilityCount`.
   - Adjusts the number of WorkerThreads based on detection rates.

2. **WorkerThread:**
   - Scans log entries for vulnerabilities using the `vulnerabilityPattern`.
   - Uses `LevenshteinDistance` to measure similarity between log entries and the pattern.

3. **LevenshteinDistance:**
   - A utility class that calculates the similarity between two strings using the Levenshtein distance algorithm.

4. **Main:**
   - The entry point of the application, initializing the `MasterThread` with the log file path and vulnerability pattern.

**Key Feature:**
- **Synchronization:**
  - The critical section involves incrementing `vulnerabilityCount`, which must be done atomically.
  - The `incrementVulnerabilityCount` method in `MasterThread.java` is synchronized to ensure mutual exclusion, preventing race conditions.
  - This synchronization mechanism ensures that no updates are lost or overwritten when multiple threads access the shared resource concurrently.
