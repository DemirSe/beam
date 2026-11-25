package com.beam.android.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.SecureRandom
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

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        try {
            (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        } catch (e: Exception) {
            // An invalidated alias (lock-screen change), an unreadable entry or
            // a broken Keystore cannot be used again: drop it and re-key. The
            // old blobs become undecryptable and the store quarantines them.
            if (e !is KeyPermanentlyInvalidatedException &&
                e !is UnrecoverableKeyException &&
                e !is KeyStoreException
            ) {
                throw e
            }
            runCatching { ks.deleteEntry(ALIAS) }
        }
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

    fun encrypt(plain: ByteArray): ByteArray {
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = cipher.doFinal(plain)
        return iv + ct
    }

    fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_BYTES) { "ciphertext too short" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE, key(),
            GCMParameterSpec(GCM_TAG_BITS, blob, 0, IV_BYTES),
        )
        return cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
    }
}
