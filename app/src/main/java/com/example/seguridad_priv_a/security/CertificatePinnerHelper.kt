package com.example.seguridad_priv_a.security

import android.content.Context
import android.util.Base64
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*

class CertificatePinnerHelper(private val context: Context) {

    // Hashes SHA-256 de los certificados esperados (debes reemplazarlos con los tuyos)
    private val pinnedCertificates = listOf(
        "sha256/TU_CERTIFICADO_HASH_PRINCIPAL",  // Ejemplo: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "sha256/TU_CERTIFICADO_HASH_BACKUP"      // Ejemplo: "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    )

    // Verifica si el certificado del servidor está en la lista permitida
    private fun verifyCertificate(chain: Array<X509Certificate>): Boolean {
        for (cert in chain) {
            val x509Cert = cert as X509Certificate
            val publicKey = x509Cert.publicKey.encoded
            val sha256 = MessageDigest.getInstance("SHA-256").digest(publicKey)
            val pin = "sha256/" + Base64.encodeToString(sha256, Base64.NO_WRAP)

            if (pinnedCertificates.contains(pin)) {
                return true
            }
        }
        return false
    }

    // Crea un TrustManager personalizado que verifica los certificados
    fun getPinnedTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                // No necesitamos verificar certificados de cliente
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (!verifyCertificate(chain)) {
                    throw CertificateException("Certificate pinning failed!")
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return arrayOf()
            }
        }
    }

    // Configura un SSLContext con nuestro TrustManager personalizado
    fun getPinnedSSLContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(getPinnedTrustManager()), null)
        return sslContext
    }

    // Ejemplo de cómo usar esto en una conexión HTTPS
    fun makeSecureRequest(url: String) {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.sslSocketFactory = getPinnedSSLContext().socketFactory

        try {
            connection.connect()
            // Leer la respuesta...
            val responseCode = connection.responseCode
            val inputStream = connection.inputStream
            // Procesar la respuesta...
        } finally {
            connection.disconnect()
        }
    }
}