package com.example.seguridad_priv_a.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.gson.Gson
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class SecurityAuditManagerTest {

    private lateinit var securityAuditManager: SecurityAuditManager
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        securityAuditManager = SecurityAuditManager(context)

        // Limpiar SharedPreferences antes de cada test
        context.getSharedPreferences("signed_audit_logs", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @After
    fun tearDown() {
        // Limpiar SharedPreferences después de cada test
        context.getSharedPreferences("signed_audit_logs", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun testLogAccessAttempt_Successful() {
        val result = securityAuditManager.logAccessAttempt("login", "user1", true)
        assertTrue(result)
    }

    @Test
    fun testLogAccessAttempt_RateLimitExceeded() {
        // Realizar más intentos de los permitidos en la ventana de tiempo
        repeat(6) {
            securityAuditManager.logAccessAttempt("sensitive_operation", "user1", true)
        }

        // El sexto intento debería fallar por rate limiting
        val result = securityAuditManager.logAccessAttempt("sensitive_operation", "user1", true)
        assertFalse(result)
    }

    @Test
    fun testLogAccessAttempt_SuspiciousActivity() {
        // Realizar varios intentos fallidos
        repeat(3) {
            securityAuditManager.logAccessAttempt("admin_access", "user1", false)
        }

        // Verificar que se generó una alerta (comprobando los logs exportados)
        val logs = securityAuditManager.exportAuditLogs()
        assertEquals(1, logs.size)
        assertTrue(logs[0].contains("Actividad sospechosa"))
    }

    @Test
    fun testSignData_VerifyStructure() {
        val testData = mapOf(
            "testKey" to "testValue",
            "timestamp" to System.currentTimeMillis()
        )

        val signedData = securityAuditManager.signData(testData)
        val jsonMap = Gson().fromJson(signedData, Map::class.java)

        // Verificar que la estructura del dato firmado es correcta
        assertTrue(jsonMap.containsKey("data"))
        assertTrue(jsonMap.containsKey("signature"))
    }

    @Test
    fun testExportAuditLogs_Empty() {
        val logs = securityAuditManager.exportAuditLogs()
        assertTrue(logs.isEmpty())
    }

    @Test
    fun testExportAuditLogs_WithData() {
        // Generar una alerta
        securityAuditManager.logAccessAttempt("login", "user1", false)
        securityAuditManager.logAccessAttempt("login", "user1", false)
        securityAuditManager.logAccessAttempt("login", "user1", false) // Debería generar alerta

        val logs = securityAuditManager.exportAuditLogs()
        assertEquals(1, logs.size)
        assertTrue(logs[0].contains("Actividad sospechosa"))
    }
}