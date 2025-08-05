package com.example.seguridad_priv_a

import android.app.Application
import android.os.Build
import androidx.annotation.RequiresApi
import com.example.seguridad_priv_a.data.DataProtectionManager
import com.example.seguridad_priv_a.security.ZeroTrustManager

@RequiresApi(Build.VERSION_CODES.O)
class PermissionsApplication : Application() {

    val dataProtectionManager by lazy { DataProtectionManager(this) }

    val zeroTrustManager by lazy { ZeroTrustManager.getInstance(this) }

    override fun onCreate() {
        super.onCreate()

        // Inicialización tradicional
        dataProtectionManager.initialize()
        dataProtectionManager.logAccess("APPLICATION", "App iniciada")

        // Inicialización simplificada de ZeroTrust
        zeroTrustManager.apply {
            // Configuración básica (opcional)
            logSecurityEvent("APP_START", "Aplicación iniciada con Zero-Trust")
        }
    }
}