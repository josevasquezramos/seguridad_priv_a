package com.example.seguridad_priv_a.forense

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import java.io.File

/**
 * Pruebas instrumentadas para el sistema de análisis forense.
 */
@RunWith(AndroidJUnit4::class)
class ForensicAnalysisSystemTest {

    private lateinit var forensicSystem: ForensicAnalysisSystem
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        forensicSystem = ForensicAnalysisSystem(context)

        // Limpiar datos de pruebas anteriores
        cleanTestData()
    }

    private fun cleanTestData() {
        val evidenceDir = File(context.filesDir, "forensic_evidence")
        if (evidenceDir.exists()) {
            evidenceDir.listFiles()?.forEach { it.delete() }
        }

        val blockchainFile = File(context.filesDir, "forensic_blockchain.json")
        if (blockchainFile.exists()) {
            blockchainFile.delete()
        }
    }

    @Test
    fun testLogEvidence_createsValidEvidence() {
        // Act
        val evidence = forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT,
            description = "Intento de acceso no autorizado",
            source = "AuthService",
            collector = "Admin"
        )

        // Assert
        assertNotNull(evidence)
        assertTrue(evidence.id.startsWith("EVID-"))
        assertEquals(ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT, evidence.type)
        assertEquals("Intento de acceso no autorizado", evidence.description)
        assertEquals("AuthService", evidence.source)
        assertEquals("Admin", evidence.collector)
        assertFalse(evidence.hash.isNullOrEmpty())
        assertEquals(1, evidence.chainOfCustody.size)
    }

    @Test
    fun testAddCustodyRecord_updatesEvidenceCorrectly() {
        // Arrange
        val evidence = forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.USER_ACTIVITY,
            description = "Registro de actividad del usuario",
            source = "UserService",
            collector = "Analyst1"
        )

        // Act
        val result = forensicSystem.evidenceManager.addCustodyRecord(
            evidenceId = evidence.id,
            action = "TRANSFER",
            actor = "Analyst2",
            notes = "Transferido para análisis"
        )

        // Assert
        assertTrue(result)

        val updatedEvidence = forensicSystem.evidenceManager.loadEvidence(evidence.id)
        assertNotNull(updatedEvidence)
        assertEquals(2, updatedEvidence?.chainOfCustody?.size)
        assertEquals("TRANSFER", updatedEvidence?.chainOfCustody?.last()?.action)
        assertEquals("Analyst2", updatedEvidence?.chainOfCustody?.last()?.actor)
    }

    @Test
    fun testVerifyChainOfCustody_returnsCorrectResult() {
        // Arrange
        val evidence1 = forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.DEVICE_INFO,
            description = "Información del dispositivo",
            source = "DeviceService",
            collector = "Tech1"
        )

        val evidence2 = forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.NETWORK_CAPTURE,
            description = "Captura de tráfico sospechoso",
            source = "NetworkMonitor",
            collector = "NetAdmin"
        )

        // Act
        val verificationResult = forensicSystem.verifyChainOfCustody()

        // Assert
        assertTrue(verificationResult.allValid)
        assertEquals(2, verificationResult.details.size)
        assertTrue(verificationResult.details.all { it.isValid })
    }

    @Test
    fun testGenerateComplianceReport_containsRequiredSections() {
        // Arrange
        forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT,
            description = "Evento de seguridad - GDPR compliance check",
            source = "ComplianceService",
            collector = "Auditor"
        )

        // Act
        val report = forensicSystem.generateComplianceReport()

        // Assert
        assertNotNull(report)
        assertTrue(report.timestamp > 0)
        assertNotNull(report.gdprCompliance)
        assertNotNull(report.ccpaCompliance)
        assertFalse(report.recommendations.isEmpty())
    }

    @Test
    fun testInvestigateIncident_createsValidReport() {
        // Arrange
        val incidentId = "INC-12345"
        forensicSystem.logEvidence(
            type = ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT,
            description = "Evento relacionado con incidente $incidentId",
            source = "SecurityMonitor",
            collector = "SecAnalyst"
        )

        // Act
        val report = forensicSystem.investigateIncident(incidentId)

        // Assert
        assertEquals(incidentId, report.incidentId)
        assertTrue(report.timestamp > 0)
        assertEquals(1, report.relatedEvidence.size)
        assertFalse(report.timeline.isEmpty())
        assertFalse(report.findings.isEmpty())
        assertFalse(report.recommendations.isEmpty())
    }
}