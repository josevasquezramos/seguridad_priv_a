package com.example.seguridad_priv_a.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

@RunWith(AndroidJUnit4::class)
class DataProtectionManagerTest {

    private lateinit var dataProtectionManager: DataProtectionManager
    private val testKey = "test_key"
    private val testValue = "test_value_${UUID.randomUUID()}"

    @Before
    fun setUp() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        dataProtectionManager = DataProtectionManager(appContext)
        dataProtectionManager.initialize()
        dataProtectionManager.clearAllData() // Limpiar datos antes de cada test
    }

    @Test
    fun testStoreAndRetrieveSecureData() {
        // Almacenar dato
        dataProtectionManager.storeSecureData(testKey, testValue)

        // Recuperar dato
        val retrievedValue = dataProtectionManager.getSecureData(testKey)

        assertEquals(testValue, retrievedValue)
    }

    @Test
    fun testDataIntegrityVerification() {
        // Almacenar dato
        dataProtectionManager.storeSecureData(testKey, testValue)

        // Verificar integridad
        val isIntegrityValid = dataProtectionManager.getSecureData(testKey) != null
        assertTrue(isIntegrityValid)
    }

    @Test
    fun testGetUserIdGeneratesAnonymousIdWhenNotExists() {
        // Limpiar user_id
        dataProtectionManager.clearAllData()

        // Obtener user ID
        val userId = dataProtectionManager.getUserId()

        assertNotNull(userId)
        assertTrue(userId.startsWith("anon_"))
    }

    @Test
    fun testAccessLogging() {
        val testCategory = "TEST_CATEGORY"
        val testAction = "Test action ${UUID.randomUUID()}"

        // Registrar log
        dataProtectionManager.logAccess(testCategory, testAction)

        // Obtener logs
        val logs = dataProtectionManager.getAccessLogs()

        // Verificar que el log existe
        assertTrue(logs.any { it.contains(testAction) })
    }

    @Test
    fun testClearAllData() {
        // Almacenar datos de prueba
        dataProtectionManager.storeSecureData(testKey, testValue)
        dataProtectionManager.logAccess("TEST", "Test log entry")

        // Verificar que los datos existen antes de limpiar
        assertNotNull(dataProtectionManager.getSecureData(testKey))
        assertFalse(dataProtectionManager.getAccessLogs().isEmpty())

        // Limpiar todo
        dataProtectionManager.clearAllData()

        // Verificar que los datos fueron eliminados
        assertNull(dataProtectionManager.getSecureData(testKey))

        // Verificar logs - puede que quede un log de la operación clear
        val logs = dataProtectionManager.getAccessLogs()
        assertTrue("Los logs deberían estar vacíos o contener solo el log de limpieza",
            logs.isEmpty() || logs.size == 1 && logs[0].contains("Todos los datos han sido borrados"))
    }

    @Test
    fun testGetDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()

        assertNotNull(info)
        assertTrue(info.isNotEmpty())
        assertEquals("AES-256-GCM", info["Encriptación"])
    }

    @Test
    fun testAnonymizeData() {
        val sensitiveData = "John Doe, 123 Main St, 555-1234"
        val anonymized = dataProtectionManager.anonymizeData(sensitiveData)

        assertNotNull(anonymized)
        assertNotEquals(sensitiveData, anonymized)
        assertTrue(anonymized.length >= sensitiveData.length) // La anonimización suele ser más larga
    }
}