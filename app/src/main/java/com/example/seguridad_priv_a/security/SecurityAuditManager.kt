package com.example.seguridad_priv_a.security

import android.content.Context
import android.util.Base64
import com.google.gson.Gson
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import androidx.core.content.edit

class SecurityAuditManager(private val context: Context) {

    // Configuración de seguridad
    private companion object {
        const val RATE_LIMIT_WINDOW_MS = 60000L // 1 minuto para rate limiting
        const val MAX_REQUESTS_PER_WINDOW = 5 // Límite de operaciones sensibles
        const val SUSPICIOUS_ACTIVITY_THRESHOLD = 3 // Intentos fallidos para alerta
    }

    private val gson = Gson()
    private val accessAttempts = ConcurrentHashMap<String, MutableList<Long>>()
    private val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()

    // Detección de accesos sospechosos
    fun logAccessAttempt(operation: String, userId: String, success: Boolean): Boolean {
        val now = System.currentTimeMillis()
        val key = "$userId-$operation"

        // Registrar intento
        accessAttempts.getOrPut(key) { mutableListOf() }.add(now)

        // Limpiar intentos antiguos (>1 minuto)
        accessAttempts[key] = accessAttempts[key]?.filter {
            now - it < RATE_LIMIT_WINDOW_MS
        }?.toMutableList() ?: mutableListOf()

        // Verificar rate limiting
        val attempts = accessAttempts[key]?.size ?: 0
        if (attempts > MAX_REQUESTS_PER_WINDOW) {
            generateAlert("Rate limit excedido", "Operación: $operation, Usuario: $userId")
            return false
        }

        // Detectar patrones anómalos (ej. múltiples fallos)
        if (!success && attempts >= SUSPICIOUS_ACTIVITY_THRESHOLD) {
            generateAlert("Actividad sospechosa", "Intento de acceso no autorizado a $operation")
        }

        return true
    }

    // Generación de alertas
    private fun generateAlert(title: String, message: String) {
        val alert = mapOf(
            "timestamp" to System.currentTimeMillis(),
            "title" to title,
            "message" to message,
            "deviceId" to UUID.randomUUID().toString()
        )
        val signedAlert = signData(alert)
        saveSignedLog(signedAlert)
    }

    // Firma digital de logs (RSA-SHA256)
    fun signData(data: Map<String, Any>): String {
        val json = gson.toJson(data)
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(keyPair.private)
            update(json.toByteArray())
        }
        val signedData = mapOf(
            "data" to data,
            "signature" to Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
        )
        return gson.toJson(signedData)
    }

    // Almacenamiento seguro de logs
    private fun saveSignedLog(signedLog: String) {
        context.getSharedPreferences("signed_audit_logs", Context.MODE_PRIVATE)
            .edit {
                putString("log_${System.currentTimeMillis()}", signedLog)
            }
    }

    // Exportar logs en formato JSON firmado
    fun exportAuditLogs(): List<String> {
        return context.getSharedPreferences("signed_audit_logs", Context.MODE_PRIVATE)
            .all
            .map { it.value.toString() }
    }
}