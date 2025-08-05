package com.example.seguridad_priv_a.security

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import net.sqlcipher.BuildConfig
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@RequiresApi(Build.VERSION_CODES.O)
class ZeroTrustManager(context: Context) {
    // Singleton pattern
    companion object {
        @Volatile private var instance: ZeroTrustManager? = null

        fun getInstance(context: Context): ZeroTrustManager {
            return instance ?: synchronized(this) {
                instance ?: ZeroTrustManager(context.applicationContext).also { instance = it }
            }
        }
    }

    // Componentes de seguridad
    private val securePrefs: EncryptedSharedPreferences
    private val mac: Mac = Mac.getInstance("HmacSHA256")
    private val secureRandom = SecureRandom()

    // Tokens de sesión
    private var sessionToken: String? = null
    private var sessionExpiry: Long = 0

    init {
        // Configuración inicial de almacenamiento seguro
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        securePrefs = EncryptedSharedPreferences.create(
            context,
            "zero_trust_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ) as EncryptedSharedPreferences

        // Generar clave HMAC inicial si no existe
        if (!securePrefs.contains("hmac_key")) {
            val keyBytes = ByteArray(32)
            secureRandom.nextBytes(keyBytes)
            securePrefs.edit().putString("hmac_key", Base64.getEncoder().encodeToString(keyBytes)).apply()
        }

        // Inicializar HMAC
        val hmacKey = Base64.getDecoder().decode(securePrefs.getString("hmac_key", ""))
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
    }

    // 1. Validación de operaciones sensibles
    @RequiresApi(Build.VERSION_CODES.O)
    fun authorizeOperation(operation: String, context: String): Boolean {
        // Verificar sesión activa
        if (!isSessionValid()) return false

        // Verificar integridad de la aplicación
        if (!verifyAppIntegrity()) return false

        // Verificar privilegios mínimos necesarios para esta operación en este contexto
        val requiredPrivilege = getRequiredPrivilege(operation, context)
        if (!hasPrivilege(requiredPrivilege)) return false

        // Registrar la operación
        logSecurityEvent("OPERATION_AUTHORIZED", "Operación: $operation, Contexto: $context")

        return true
    }

    // 2. Principio de menor privilegio por contexto
    fun getRequiredPrivilege(operation: String, context: String): String {
        // Mapeo simplificado de operaciones a privilegios requeridos
        return when {
            operation.contains("read") && context.contains("settings") -> "settings_read"
            operation.contains("write") && context.contains("settings") -> "settings_write"
            operation.contains("delete") -> "admin"
            else -> "basic"
        }
    }

    fun hasPrivilege(requiredPrivilege: String): Boolean {
        val userPrivileges = getUserPrivileges()
        return userPrivileges.contains(requiredPrivilege)
    }

    private fun getUserPrivileges(): Set<String> {
        // Obtener privilegios del usuario actual desde almacenamiento seguro
        return securePrefs.getStringSet("user_privileges", setOf("basic")) ?: setOf("basic")
    }

    // 3. Gestión de sesiones con tokens temporales
    @RequiresApi(Build.VERSION_CODES.O)
    fun createSession(userId: String, privileges: Set<String>, durationMinutes: Int = 30): String {
        // Generar token de sesión seguro
        val token = generateSecureToken()
        val expiry = System.currentTimeMillis() + durationMinutes * 60 * 1000

        // Almacenar información de sesión
        securePrefs.edit().apply {
            putString("session_token", token)
            putLong("session_expiry", expiry)
            putStringSet("user_privileges", privileges)
            apply()
        }

        sessionToken = token
        sessionExpiry = expiry

        logSecurityEvent("SESSION_CREATED", "Usuario: ${anonymizeData(userId)}")

        return token
    }

    fun isSessionValid(): Boolean {
        val storedToken = securePrefs.getString("session_token", null)
        val storedExpiry = securePrefs.getLong("session_expiry", 0)

        // Verificar token y tiempo de expiración
        return storedToken != null &&
                storedToken == sessionToken &&
                System.currentTimeMillis() < storedExpiry
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun endSession() {
        logSecurityEvent("SESSION_ENDED", "Usuario: ${getCurrentUserId()}")
        securePrefs.edit().remove("session_token").remove("session_expiry").apply()
        sessionToken = null
        sessionExpiry = 0
    }

    // 4. Attestation de integridad de la aplicación
    fun verifyAppIntegrity(): Boolean {
        // Implementación simplificada - en producción usar SafetyNet Attestation o Play Integrity API
        val storedHash = securePrefs.getString("app_integrity_hash", null)

        if (storedHash == null) {
            // Primera ejecución, guardar hash esperado
            val expectedHash = calculateAppHash()
            securePrefs.edit().putString("app_integrity_hash", expectedHash).apply()
            return true
        }

        return calculateAppHash() == storedHash
    }

    private fun calculateAppHash(): String {
        // En una implementación real, esto calcularía el hash del paquete de la aplicación
        // Aquí usamos un valor simulado para la demo
        return "dummy_app_hash_${BuildConfig.VERSION_NAME}"
    }

    // Herramientas de seguridad
    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateSecureToken(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun generateHmac(data: String): String {
        return Base64.getEncoder().encodeToString(mac.doFinal(data.toByteArray()))
    }

    fun anonymizeData(data: String): String {
        return data.replace(Regex("[0-9]"), "*")
    }

    // Registro de eventos de seguridad
    @RequiresApi(Build.VERSION_CODES.O)
    fun logSecurityEvent(type: String, details: String) {
        val timestamp = System.currentTimeMillis()
        val eventId = UUID.randomUUID().toString()

        val eventData = """
            {
                "event_id": "$eventId",
                "timestamp": $timestamp,
                "type": "$type",
                "details": "$details",
                "user": "${getCurrentUserId()}",
                "integrity_check": ${verifyAppIntegrity()}
            }
        """.trimIndent()

        val signedEvent = generateHmac(eventData)

        // Almacenar evento firmado
        securePrefs.edit().putString("security_event_$eventId", signedEvent).apply()
    }

    fun getCurrentUserId(): String {
        return securePrefs.getString("current_user_id", "anonymous") ?: "anonymous"
    }
}