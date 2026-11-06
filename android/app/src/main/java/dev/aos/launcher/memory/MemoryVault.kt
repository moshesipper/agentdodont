package dev.aos.launcher.memory

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Memory at rest: AES-256-GCM, with the key generated inside the Android Keystore (hardware-backed
 * on the S22, never exportable), in app-private storage. Backups are off for the app, so the file
 * only exists on this phone, and without the key it is noise.
 */
class MemoryVault(context: Context) {
    private val file = File(context.filesDir, "memory.enc")

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun load(): List<MemoryItem> {
        if (!file.exists()) return emptyList()
        val plain = DataInputStream(file.inputStream()).use { input ->
            val iv = ByteArray(input.readInt()).also { input.readFully(it) }
            val ct = input.readBytes()
            Cipher.getInstance(TRANSFORM).run {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
                doFinal(ct)
            }
        }
        val arr = JSONArray(String(plain, Charsets.UTF_8))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            MemoryItem(o.getInt("id"), o.getString("text"), Origin.valueOf(o.getString("origin")),
                o.getLong("created"), o.getLong("updated"))
        }
    }

    fun save(items: List<MemoryItem>) {
        val json = JSONArray(items.map {
            JSONObject().put("id", it.id).put("text", it.text).put("origin", it.origin.name)
                .put("created", it.createdAt).put("updated", it.updatedAt)
        }).toString()
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ct = cipher.doFinal(json.toByteArray(Charsets.UTF_8))
        val tmp = File(file.path + ".tmp")
        DataOutputStream(tmp.outputStream()).use { out ->
            out.writeInt(cipher.iv.size)
            out.write(cipher.iv)
            out.write(ct)
        }
        tmp.renameTo(file)
    }

    companion object {
        private const val ALIAS = "aos_memory"
        private const val TRANSFORM = "AES/GCM/NoPadding"
    }
}

/** The app-wide memory, loaded once from the vault; every change is re-encrypted to disk. */
object Memory {
    @Volatile private var book: MemoryBook? = null

    fun init(context: Context) {
        if (book != null) return
        val vault = MemoryVault(context.applicationContext)
        val items = try {
            vault.load()
        } catch (e: Exception) {
            // Unreadable (e.g. the keystore key was reset): keep the file aside instead of
            // overwriting it on the next save, and start empty rather than crash the home screen.
            android.util.Log.w("AgentDoDont", "memory unreadable, starting empty: ${e::class.simpleName}")
            val f = File(context.filesDir, "memory.enc")
            f.renameTo(File(context.filesDir, "memory.enc.unreadable-${System.currentTimeMillis()}"))
            emptyList()
        }
        book = MemoryBook(items) { vault.save(it) }
    }

    /** For tests and before init: an in-memory book that persists nowhere. */
    fun book(): MemoryBook = book ?: MemoryBook().also { book = it }
}
