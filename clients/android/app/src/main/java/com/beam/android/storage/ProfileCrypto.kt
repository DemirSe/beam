package com.beam.android.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android Keystore AES-256-GCM helper (key alias `beam_profiles_v1`). */
internal object ProfileCrypto {
    private const val ALIAS = "beam_profiles_v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12

    private fun isBrokenKeyError(e: Exception): Boolean =
        e is KeyPermanentlyInvalidatedException ||
            e is UnrecoverableKeyException ||
            e is KeyStoreException ||
            e is InvalidKeyException

    private fun deleteAlias() {
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.deleteEntry(ALIAS)
        }
    }

    private fun generateKey(): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        try {
            (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        } catch (e: Exception) {
            if (!isBrokenKeyError(e)) throw e
            runCatching { ks.deleteEntry(ALIAS) }
        }
        return generateKey()
    }

    fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // Android Keystore enforces randomized encryption by default and
        // rejects a caller-provided encryption IV, so ask the cipher for one.
        // If Cipher.init() surfaces an invalidated/broken alias, drop and re-key once.
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key())
        } catch (e: Exception) {
            if (!isBrokenKeyError(e)) throw e
            deleteAlias()
            cipher.init(Cipher.ENCRYPT_MODE, generateKey())
        }
        val iv = cipher.iv
        check(iv.size == IV_BYTES) { "unexpected IV length" }
        return iv + cipher.doFinal(plain)
    }

    fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_BYTES) { "ciphertext too short" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(
                Cipher.DECRYPT_MODE, key(),
                GCMParameterSpec(GCM_TAG_BITS, blob, 0, IV_BYTES),
            )
        } catch (e: Exception) {
            if (isBrokenKeyError(e)) {
                // Drop the invalidated alias so subsequent encrypt() calls can
                // create a fresh key; the caller quarantines the unreadable blob.
                deleteAlias()
            }
            throw e
        }
        return cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
    }
}
