package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.seguridad_priv_a.security.AdvancedAnonymizer
import com.example.seguridad_priv_a.security.SecurityAuditManager
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.codec.binary.Hex
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {
    
    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences

    private val auditManager = SecurityAuditManager(context)

    private val advancedAnonymizer = AdvancedAnonymizer()

    private companion object {
        const val KEY_ROTATION_INTERVAL = 30L * 24 * 60 * 60 * 1000 // 30 días
        const val HMAC_ALGORITHM = "HmacSHA256"
        const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
        const val PBKDF2_ITERATIONS = 10000
        const val DERIVED_KEY_LENGTH = 256 // bits
        const val SALT_LENGTH = 16 // bytes
    }

    fun rotateEncryptionKey(): Boolean {
        return try {
            // Verificar si es necesario rotar la clave
            val lastRotation = encryptedPrefs.getLong("last_key_rotation", 0L)
            val currentTime = System.currentTimeMillis()

            if (currentTime - lastRotation > KEY_ROTATION_INTERVAL) {
                // 1. Migrar datos existentes a nueva clave
                val allData = HashMap<String, String?>()
                for (entry in encryptedPrefs.all) {
                    allData[entry.key] = entry.value.toString()
                }

                // 2. Crear nueva clave maestra
                val newMasterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .setRequestStrongBoxBacked(true) // Usar hardware seguro si disponible
                    .build()

                // 3. Recrear EncryptedSharedPreferences con nueva clave
                encryptedPrefs = EncryptedSharedPreferences.create(
                    context,
                    "secure_prefs",
                    newMasterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )

                // 4. Restaurar datos con nueva encriptación
                for ((key, value) in allData) {
                    if (value != null) {
                        encryptedPrefs.edit().putString(key, value).apply()
                    }
                }

                // 5. Registrar fecha de rotación
                encryptedPrefs.edit().putLong("last_key_rotation", currentTime).apply()
                logAccess("KEY_MANAGEMENT", "Clave maestra rotada exitosamente")
                true
            } else {
                false // No era necesario rotar aún
            }
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error al rotar clave: ${e.message}")
            false
        }
    }

    private fun generateHMAC(data: String, key: String): String {
        val secretKeySpec = SecretKeySpec(key.toByteArray(Charsets.UTF_8), HMAC_ALGORITHM)
        val mac = Mac.getInstance(HMAC_ALGORITHM).apply {
            init(secretKeySpec)
        }
        return Hex.encodeHexString(mac.doFinal(data.toByteArray(Charsets.UTF_8)))
    }

    fun verifyDataIntegrity(key: String): Boolean {
        return try {
            val data = encryptedPrefs.getString(key, null) ?: return false
            val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false

            // Generar HMAC con clave derivada del ID de usuario
            val userSpecificKey = deriveUserKey(key)
            val calculatedHmac = generateHMAC(data, userSpecificKey)

            if (calculatedHmac == storedHmac) {
                true
            } else {
                logAccess("SECURITY_ALERT", "Integridad comprometida para clave: $key")
                false
            }
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error verificando integridad: ${e.message}")
            false
        }
    }

    private fun deriveUserKey(baseKey: String): String {
        // Obtener salt único por usuario (almacenado de forma segura)
        val userSalt = encryptedPrefs.getString("user_salt", null) ?: run {
            val newSalt = generateSecureSalt()
            encryptedPrefs.edit().putString("user_salt", newSalt).apply()
            newSalt
        }

        // Usar PBKDF2 para derivación de clave
        val iterations = PBKDF2_ITERATIONS
        val keyLength = DERIVED_KEY_LENGTH // bits

        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val spec = PBEKeySpec(
            (baseKey + userSalt).toCharArray(),
            userSalt.toByteArray(Charsets.UTF_8),
            iterations,
            keyLength
        )

        val keyBytes = factory.generateSecret(spec).encoded
        return Hex.encodeHexString(keyBytes)
    }

    private fun generateSecureSalt(): String {
        val secureRandom = SecureRandom()
        val salt = ByteArray(SALT_LENGTH)
        secureRandom.nextBytes(salt)
        return Hex.encodeHexString(salt)
    }

    fun initialize() {
        try {
            // Crear o obtener la clave maestra
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
                
            // Crear SharedPreferences encriptado para datos sensibles
            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            
            // SharedPreferences normal para logs de acceso (no son datos sensibles críticos)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
            
        } catch (e: Exception) {
            // Fallback a SharedPreferences normales si falla la encriptación
            encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        }
    }
    
    fun storeSecureData(key: String, value: String) {
        try {
            rotateEncryptionKey() // Verificar rotación primero

            // Generar HMAC con clave derivada
            val userKey = deriveUserKey(key)
            val hmac = generateHMAC(value, userKey)

            encryptedPrefs.edit().apply {
                putString(key, value)
                putString("${key}_hmac", hmac)
                apply()
            }
            logAccess("DATA_STORAGE", "Dato almacenado con HMAC: $key")
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error almacenando dato: ${e.message}")
        }
    }

    fun getSecureData(key: String): String? {
        val userId = getUserId()
        if (!auditManager.logAccessAttempt("access_$key", userId, true)) {
            return null
        }
        try {
            val data = encryptedPrefs.getString(key, null) ?: return null
            if (!verifyDataIntegrity(key)) {
                logAccess("SECURITY_ALERT", "Intento de acceso a dato comprometido: $key")
                return null
            }
            logAccess("DATA_ACCESS", "Dato accedido: $key")
            return data
        } catch (e: Exception) {
            logAccess("SECURITY_ERROR", "Error obteniendo dato: ${e.message}")
            return null
        }
    }

    fun getUserId(): String {
        return encryptedPrefs.getString("user_id", generateAnonymousUserId()) ?: generateAnonymousUserId()
    }

    private fun generateAnonymousUserId(): String {
        val newId = "anon_${UUID.randomUUID().toString().take(8)}"
        encryptedPrefs.edit().putString("user_id", newId).apply()
        return newId
    }

    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"
        
        // Obtener logs existentes
        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\\n$logEntry"
        }
        
        // Guardar logs actualizados
        accessLogPrefs.edit().putString("logs", newLogs).apply()
        
        // Limitar el número de logs (mantener solo los últimos 100)
        val logLines = newLogs.split("\\n")
        if (logLines.size > 100) {
            val trimmedLogs = logLines.takeLast(100).joinToString("\\n")
            accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
        }
    }
    
    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\\n").reversed() // Mostrar los más recientes primero
        }
    }
    
    fun clearAllData() {
        // Limpiar datos encriptados
        encryptedPrefs.edit().clear().apply()
        
        // Limpiar logs
        accessLogPrefs.edit().clear().apply()
        
        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }
    
    fun getDataProtectionInfo(): Map<String, String> {
        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Última limpieza" to (getSecureData("last_cleanup") ?: "Nunca"),
            "Estado de seguridad" to "Activo"
        )
    }
    
    fun anonymizeData(data: String): String {
        return advancedAnonymizer.anonymizeData(data)
    }
}