/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package jvm.library;

import org.junit.Test;
import static org.junit.Assert.*;

public class LibraryTest {
    @Test public void testGenerateKeyPair() {
        // Library classUnderTest = new Library();
        assertTrue("someLibraryMethod should return 'true'", Library.generateKeyPair("\\keyTest\\pb.key", "\\keyTest\\pv.key"));
    }
}
