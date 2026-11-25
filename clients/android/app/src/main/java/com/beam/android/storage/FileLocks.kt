package com.beam.android.storage

import java.io.File
import java.io.RandomAccessFile

// FileLock throws OverlappingFileLockException when two threads of this
// process overlap, so the JVM monitor queues them before the OS lock.
private val jvmLockMutex = Any()

/**
 * Cross-process mutex for a store file. The UI and `:vpn` are separate
 * processes, so a `synchronized` block alone is not enough.
 */
internal fun <T> withFileLock(lockFile: File, block: () -> T): T = synchronized(jvmLockMutex) {
    lockFile.parentFile?.mkdirs()
    RandomAccessFile(lockFile, "rw").use { raf ->
        val lock = raf.channel.lock()
        try {
            block()
        } finally {
            lock.release()
        }
    }
}
