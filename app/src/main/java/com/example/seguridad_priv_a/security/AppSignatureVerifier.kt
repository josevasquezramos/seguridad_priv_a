package com.example.seguridad_priv_a.security

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.example.seguridad_priv_a.PermissionsApplication
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

class AppSignatureVerifier(private val context: Context) {

    // Hash SHA-256 de la firma esperada (debe reemplazarse con tu firma real)
    private val expectedSignatureHash = "YOUR_APP_SIGNATURE_SHA256_HASH"

    @RequiresApi(Build.VERSION_CODES.O)
    fun verifyAppSignature(): Boolean {
        try {
            // Obtener las firmas del paquete
            val packageName = context.packageName
            val packageInfo: PackageInfo = context.packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNATURES
            )

            // Calcular el hash SHA-256 de cada firma
            for (signature in packageInfo.signatures!!) {
                val signatureHash = calculateSHA256(signature.toByteArray())
                if (signatureHash == expectedSignatureHash) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Registrar el error
            (context.applicationContext as PermissionsApplication)
                .dataProtectionManager.logAccess("SECURITY_ERROR", "Error verificando firma: ${e.message}")
        }

        return false
    }

    private fun calculateSHA256(bytes: ByteArray): String {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(bytes)
            Base64.encodeToString(digest, Base64.NO_WRAP)
        } catch (e: NoSuchAlgorithmException) {
            ""
        }
    }
}