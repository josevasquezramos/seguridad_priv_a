package com.example.seguridad_priv_a.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Date

@RunWith(AndroidJUnit4::class)
class SecurityComponentsTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun testStringObfuscator() {
        // Verificamos que el ofuscador/desofuscador funciona correctamente
        val testString = "test_string"
        val obfuscated = StringObfuscator.obfuscateString(testString)
        assertNotEquals(testString, obfuscated)

        val deobfuscated =
            _root_ide_package_.java.lang.String(StringObfuscator.decodeBase64(obfuscated))
        assertEquals(testString, deobfuscated)

        // Verificamos los métodos de acceso
        assertNotNull(StringObfuscator.getMasterKeyAlias())
        assertNotNull(StringObfuscator.getSecurePrefsName())
        assertNotNull(StringObfuscator.getHmacKey())
    }

    @Test
    fun testCertificatePinnerHelper() {
        val pinner = CertificatePinnerHelper(context)

        // Probamos que podemos crear el SSLContext sin errores
        val sslContext = pinner.getPinnedSSLContext()
        assertNotNull(sslContext)

        // Probamos con un certificado que debería fallar (simulado)
        val fakeCertificates = arrayOf(
            object : X509Certificate() {
                override fun getPublicKey() = throw CertificateException("Test exception")
                override fun checkValidity() {}
                override fun getVersion() = 0
                override fun getSerialNumber() = null
                override fun getIssuerDN() = null
                override fun getSubjectDN() = null
                override fun getNotBefore() = null
                override fun getNotAfter() = null
                override fun getSigAlgName() = ""
                override fun getSigAlgOID() = ""
                override fun getSigAlgParams() = ByteArray(0)
                override fun getSignature() = ByteArray(0)
                override fun getTBSCertificate() = ByteArray(0)
                override fun getIssuerUniqueID() = BooleanArray(0)
                override fun getSubjectUniqueID() = BooleanArray(0)
                override fun getBasicConstraints() = 0
                override fun getEncoded() = ByteArray(0)
                override fun getExtendedKeyUsage() = null
                override fun getKeyUsage() = null
                override fun hasUnsupportedCriticalExtension() = false
                override fun getCriticalExtensionOIDs() = null
                override fun getNonCriticalExtensionOIDs() = null
                override fun getExtensionValue(oid: String?) = null
                override fun verify(key: PublicKey?) {}
                override fun verify(key: PublicKey?, sigProvider: String?) {}
                override fun toString() = ""
                override fun checkValidity(date: Date?) {}
            }
        )

        val trustManager = pinner.getPinnedTrustManager()
        try {
            trustManager.checkServerTrusted(fakeCertificates as Array<out X509Certificate?>?, "RSA")
            fail("Expected CertificateException")
        } catch (e: CertificateException) {
            // Esperado
        }
    }
}