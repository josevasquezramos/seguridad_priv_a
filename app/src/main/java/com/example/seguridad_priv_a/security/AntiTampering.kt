package com.example.seguridad_priv_a.security

import android.content.Context
import android.os.Build
import android.os.Debug
import android.provider.Settings
import androidx.annotation.RequiresApi
import com.example.seguridad_priv_a.PermissionsApplication
import java.io.File

class AntiTampering(private val context: Context) {

    // Detectar si el dispositivo es un emulador
    fun isRunningOnEmulator(): Boolean {
        return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.PRODUCT.contains("sdk_google") ||
                Build.PRODUCT.contains("google_sdk") ||
                Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("sdk_x86") ||
                Build.PRODUCT.contains("vbox86p") ||
                Build.PRODUCT.contains("emulator") ||
                Build.PRODUCT.contains("simulator") ||
                isDebuggerConnected() ||
                checkDebuggerNative() // Método nativo para detección adicional
    }

    // Detectar si el depurador está conectado
    fun isDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    // Método nativo para detección avanzada de debugging
    private external fun checkDebuggerNative(): Boolean

    // Verificar si se está ejecutando en un entorno root
    fun isDeviceRooted(): Boolean {
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true
        }

        // Verificar archivos comunes de root
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        return paths.any { File(it).exists() }
    }

    // Verificar si se permite la instalación desde fuentes desconocidas
    fun isUnknownSourcesEnabled(): Boolean {
        return try {
            Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS) == 1
        } catch (e: Exception) {
            false
        }
    }

    // Inicializar las comprobaciones de seguridad
    @RequiresApi(Build.VERSION_CODES.O)
    fun performSecurityChecks(): Boolean {
        if (isRunningOnEmulator()) {
            logSecurityEvent("RUNNING_ON_EMULATOR")
            return false
        }

        if (isDebuggerConnected()) {
            logSecurityEvent("DEBUGGER_DETECTED")
            return false
        }

        if (isDeviceRooted()) {
            logSecurityEvent("ROOT_DETECTED")
            return false
        }

        if (isUnknownSourcesEnabled()) {
            logSecurityEvent("UNKNOWN_SOURCES_ENABLED")
            return false
        }

        return true
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun logSecurityEvent(event: String) {
        // Registrar el evento de seguridad
        (context.applicationContext as PermissionsApplication)
            .dataProtectionManager.logAccess("SECURITY_ALERT", "Tampering detected: $event")
    }

    companion object {
        // Cargar la biblioteca nativa
        init {
            System.loadLibrary("security-checks")
        }
    }
}