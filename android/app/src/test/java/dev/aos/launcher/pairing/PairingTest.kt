package dev.aos.launcher.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingTest {
    private val fp = "ab".repeat(32)

    @Test fun parsesTheQrLink() {
        val l = PairLink.parseUri("agentdodont://pair?a=192.168.1.20:8788&c=01234567&f=${fp.uppercase()}")!!
        assertEquals(PairLink("192.168.1.20:8788", "01234567", fp), l)
        assertEquals("ABABABAB-ABABABAB", l.shortFingerprint())
    }

    @Test fun rejectsMalformedOrOffNetworkLinks() {
        for (u in listOf(
            "agentdodont://pair?a=192.168.1.20:8788&c=1234&f=$fp", // short code
            "agentdodont://pair?a=192.168.1.20:8788&c=01234567&f=abc", // bad fingerprint
            "agentdodont://pair?a=8.8.8.8:8788&c=01234567&f=$fp", // internet address
            "agentdodont://pair?a=evil.example.com:443&c=01234567&f=$fp", // public hostname
            "https://pair?a=192.168.1.20&c=01234567", // wrong scheme
            "agentdodont://other?a=192.168.1.20&c=01234567",
        )) assertNull(u, PairLink.parseUri(u))
    }

    @Test fun typedPairingHasNoFingerprintSoTheProofDecides() {
        assertEquals(PairLink("192.168.1.20:8788", "12345678", null), PairLink.parseTyped("pair 192.168.1.20:8788 1234 5678"))
        assertEquals(PairLink("laptop.local:8788", "12345678", null), PairLink.parseTyped("Pair laptop.local:8788 1234-5678"))
        assertNull(PairLink.parseTyped("pair 203.0.113.9:8788 12345678"))
        assertNull(PairLink.parseTyped("pair the bluetooth speaker"))
    }

    @Test fun homeNetworkAddresses() {
        for (h in listOf("10.0.0.5", "172.16.1.1", "172.31.255.1", "192.168.0.10", "127.0.0.1", "laptop.local")) {
            assertTrue(h, PairLink.isLocalNetwork(h))
        }
        for (h in listOf("172.32.0.1", "8.8.8.8", "192.169.1.1", "example.com", "1.2.3")) assertFalse(h, PairLink.isLocalNetwork(h))
    }

    @Test fun proofMatchesThePythonRelay() {
        // Vector from agentdodont.pairing.proof("01234567", "n"*32, "AB"*32): both sides must agree.
        assertEquals("7e43406ed19dd129de80ab2da9411cacfff2bbc64758d9ca7e2aaa343b9cbe69",
            PairingCrypto.proof("01234567", "n".repeat(32), "AB".repeat(32)))
    }

    @Test fun pinnedTrustAcceptsOnlyTheFingerprint() {
        val cert = object : java.security.cert.X509Certificate() {
            override fun getEncoded() = byteArrayOf(1, 2, 3)
            override fun checkValidity() {}
            override fun checkValidity(date: java.util.Date?) {}
            override fun getVersion() = 3
            override fun getSerialNumber() = java.math.BigInteger.ONE
            override fun getIssuerDN() = null
            override fun getSubjectDN() = null
            override fun getNotBefore() = null
            override fun getNotAfter() = null
            override fun getTBSCertificate() = ByteArray(0)
            override fun getSignature() = ByteArray(0)
            override fun getSigAlgName() = ""
            override fun getSigAlgOID() = ""
            override fun getSigAlgParams() = null
            override fun getIssuerUniqueID() = null
            override fun getSubjectUniqueID() = null
            override fun getKeyUsage() = null
            override fun getBasicConstraints() = 0
            override fun verify(key: java.security.PublicKey?) {}
            override fun verify(key: java.security.PublicKey?, sigProvider: String?) {}
            override fun toString() = "fake"
            override fun getPublicKey() = null
            override fun hasUnsupportedCriticalExtension() = false
            override fun getCriticalExtensionOIDs() = null
            override fun getNonCriticalExtensionOIDs() = null
            override fun getExtensionValue(oid: String?) = null
        }
        val right = PairingCrypto.sha256Hex(byteArrayOf(1, 2, 3))
        PairingCrypto.Pinned(right).checkServerTrusted(arrayOf(cert), "ECDHE")
        val wrong = runCatching { PairingCrypto.Pinned(fp).checkServerTrusted(arrayOf(cert), "ECDHE") }
        assertTrue(wrong.exceptionOrNull() is java.security.cert.CertificateException)
        val tofu = PairingCrypto.Pinned(null).apply { checkServerTrusted(arrayOf(cert), "ECDHE") }
        assertEquals(right, tofu.seen)
    }
}
