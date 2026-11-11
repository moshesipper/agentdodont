package dev.agentdodont.app.pairing

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Pairing with the laptop relay over Wi-Fi (release builds: no adb). See agentdodont/pairing.py for
 * the protocol. The relay's certificate is pinned by its SHA-256 fingerprint; the relay must prove
 * it knows the one-time code before the phone reveals it.
 */
data class PairLink(val host: String, val code: String, val fingerprint: String?) {
    companion object {
        private val HOST = Regex("""^([0-9.]+|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)(:\d{1,5})?$""")
        private val CODE = Regex("""^\d{8}$""")
        private val FP = Regex("""^[0-9a-fA-F]{64}$""")
        private val TYPED = Regex("""^pair\s+(\S+)\s+(\d{4}[\s-]?\d{4})$""", RegexOption.IGNORE_CASE)

        /** The QR link  agentdodont://pair?a=<host:port>&c=<code>&f=<fingerprint> , or null if malformed. */
        fun parseUri(uri: String): PairLink? {
            val u = try { URI(uri) } catch (e: Exception) { return null }
            if (u.scheme != "agentdodont" || u.host != "pair") return null
            val q = u.rawQuery?.split('&')?.mapNotNull { kv -> kv.split('=', limit = 2).takeIf { it.size == 2 } }
                ?.associate { it[0] to it[1] } ?: return null
            return build(q["a"], q["c"], q["f"])
        }

        /** Typed in the intent box:  pair 192.168.1.20:8788 1234 5678  (no fingerprint: the proof decides). */
        fun parseTyped(text: String): PairLink? =
            TYPED.matchEntire(text.trim())?.let { m -> build(m.groupValues[1], m.groupValues[2].filter { it.isDigit() }, null) }

        private fun build(host: String?, code: String?, fp: String?): PairLink? {
            if (host == null || code == null || !HOST.matches(host) || !CODE.matches(code)) return null
            if (fp != null && !FP.matches(fp)) return null
            if (!isLocalNetwork(host.substringBefore(':'))) return null
            return PairLink(host, code, fp?.lowercase())
        }

        /** Only home-network (or loopback) addresses: pairing never points the phone at the internet. */
        fun isLocalNetwork(h: String): Boolean {
            val p = h.split('.').mapNotNull { it.toIntOrNull() }
            if (p.size == 4 && h.count { it == '.' } == 3 && p.all { it in 0..255 }) {
                return p[0] == 10 || (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168) || p[0] == 127
            }
            return h.endsWith(".local") // mDNS names on the home network
        }
    }

    /** The first 16 hex digits, as the laptop shows them, to compare by eye. */
    fun shortFingerprint() = fingerprint?.let { "${it.substring(0, 8)}-${it.substring(8, 16)}".uppercase() }
}

object PairingCrypto {
    fun proof(code: String, nonce: String, fingerprint: String): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(code.toByteArray(), "HmacSHA256")) }
        return mac.doFinal((nonce + fingerprint.lowercase()).toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    fun equal(a: String, b: String) = MessageDigest.isEqual(a.toByteArray(), b.toByteArray())

    /**
     * Trust exactly one certificate: the one with [fingerprint]. With null, accept any but record
     * what was seen (used only during pairing, where the code proof then decides).
     */
    class Pinned(private val fingerprint: String?) : X509TrustManager {
        @Volatile var seen: String? = null
            private set

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String?) {
            val fp = sha256Hex(chain.firstOrNull()?.encoded ?: throw CertificateException("no certificate"))
            seen = fp
            if (fingerprint != null && !equal(fp, fingerprint)) throw CertificateException("relay certificate doesn't match")
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw CertificateException("not a server")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

        val socketFactory: SSLSocketFactory by lazy {
            SSLContext.getInstance("TLS").apply { init(null, arrayOf(this@Pinned), SecureRandom()) }.socketFactory
        }
    }
}

/** The relay answered and said no (wrong or used code...), as opposed to being unreachable. */
class RelayRefused(message: String) : IOException(message)

/** A paired relay, as stored in app-private files. */
data class Paired(val url: String, val fingerprint: String, val deviceId: String, val token: String)

object PairingStore {
    private fun meta(c: Context) = File(c.filesDir, "pairing.json")
    private fun token(c: Context) = File(c.filesDir, "pairing_token")

    fun load(c: Context): Paired? = try {
        val o = JSONObject(meta(c).readText())
        Paired(o.getString("url"), o.getString("fp"), o.getString("device"), token(c).readText().trim())
    } catch (e: Exception) {
        null
    }

    fun save(c: Context, p: Paired) {
        token(c).writeText(p.token)
        meta(c).writeText(JSONObject().put("url", p.url).put("fp", p.fingerprint).put("device", p.deviceId).toString())
    }

    fun clear(c: Context) {
        token(c).delete()
        meta(c).delete()
    }

    /**
     * Run the pairing handshake (network: call off the main thread). Returns the pairing, or
     * throws IOException with a message fit to show the user.
     */
    fun pair(link: PairLink, deviceName: String): Paired {
        val tm = PairingCrypto.Pinned(link.fingerprint)
        val base = "https://${link.host}"
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

        val hello = post(tm, "$base/pair/hello", JSONObject().put("nonce", nonce))
        val seen = tm.seen ?: throw IOException("no certificate from the relay")
        if (!PairingCrypto.equal(hello.optString("proof"), PairingCrypto.proof(link.code, nonce, seen))) {
            throw RelayRefused("this isn't the relay that showed the code (its proof didn't match); nothing was sent")
        }
        val done = post(tm, "$base/pair/complete", JSONObject().put("code", link.code).put("name", deviceName))
        return Paired(base, seen, done.getString("device_id"), done.getString("token"))
    }

    /** GET /health on a paired relay, pinned. */
    fun healthy(p: Paired): Boolean = try {
        val c = open(PairingCrypto.Pinned(p.fingerprint), "${p.url}/health")
        try { c.responseCode in 200..499 } finally { c.disconnect() }
    } catch (e: IOException) {
        false
    }

    private fun open(tm: PairingCrypto.Pinned, url: String): HttpsURLConnection =
        (URL(url).openConnection() as HttpsURLConnection).apply {
            sslSocketFactory = tm.socketFactory
            hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true } // identity = pinned certificate
            connectTimeout = 4000
            readTimeout = 8000
        }

    private fun post(tm: PairingCrypto.Pinned, url: String, body: JSONObject): JSONObject {
        val c = open(tm, url)
        try {
            c.requestMethod = "POST"
            c.doOutput = true
            c.setRequestProperty("content-type", "application/json")
            c.outputStream.use { it.write(body.toString().toByteArray()) }
            val ok = c.responseCode in 200..299
            val text = (if (ok) c.inputStream else c.errorStream)?.bufferedReader()?.readText().orEmpty()
            val json = try { JSONObject(text) } catch (e: Exception) { JSONObject() }
            if (!ok) {
                val msg = json.optJSONObject("error")?.optString("message")?.removePrefix("relay: ") ?: "HTTP ${c.responseCode}"
                throw RelayRefused(msg)
            }
            return json
        } finally {
            c.disconnect()
        }
    }
}
