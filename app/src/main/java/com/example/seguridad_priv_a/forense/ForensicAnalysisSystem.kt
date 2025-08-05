package com.example.seguridad_priv_a.forense

import android.content.Context
import com.google.gson.Gson
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class ForensicAnalysisSystem(private val context: Context) {
    val evidenceManager = EvidenceManager(context)
    val blockchainLogger = BlockchainLogger(context)
    val complianceReporter = ComplianceReporter(context)
    private val incidentInvestigator = IncidentInvestigator(context)

    fun logEvidence(
        type: EvidenceType,
        description: String,
        source: String,
        collector: String
    ): ForensicEvidence {
        val evidence = evidenceManager.createEvidence(type, description, source, collector)
        blockchainLogger.addBlock(
            "NEW_EVIDENCE",
            "Evidence ID: ${evidence.id}, Type: ${evidence.type}, Source: ${evidence.source}"
        )
        return evidence
    }

    fun generateComplianceReport(): ComplianceReport {
        return complianceReporter.generateCombinedReport()
    }

    fun investigateIncident(incidentId: String): IncidentReport {
        return incidentInvestigator.investigate(incidentId)
    }

    fun verifyChainOfCustody(): VerificationResult {
        return evidenceManager.verifyAllEvidence()
    }

    enum class EvidenceType {
        LOG_FILE, DATABASE_RECORD, SCREENSHOT, NETWORK_CAPTURE,
        MEMORY_DUMP, DEVICE_INFO, USER_ACTIVITY, SECURITY_EVENT,
        UNAUTHORIZED_ACCESS
    }
}

class EvidenceManager(private val context: Context) {
    private val gson = Gson()
    private val evidenceDir = File(context.filesDir, "forensic_evidence")

    init {
        if (!evidenceDir.exists()) {
            evidenceDir.mkdirs()
        }
    }

    fun createEvidence(
        type: ForensicAnalysisSystem.EvidenceType,
        description: String,
        source: String,
        collector: String
    ): ForensicEvidence {
        val evidenceId = "EVID-${UUID.randomUUID().toString().substring(0, 8)}"
        val timestamp = System.currentTimeMillis()
        val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(timestamp))

        val evidence = ForensicEvidence(
            id = evidenceId,
            type = type,
            description = description,
            source = source,
            creationDate = date,
            collector = collector,
            chainOfCustody = mutableListOf(
                CustodyRecord(
                    action = "COLLECTION",
                    actor = collector,
                    timestamp = timestamp,
                    location = "DEVICE",
                    notes = "Initial evidence collection"
                )
            ),
            hash = ""
        )

        evidence.hash = calculateEvidenceHash(evidence)
        saveEvidence(evidence)
        return evidence
    }

    fun addCustodyRecord(
        evidenceId: String,
        action: String,
        actor: String,
        notes: String
    ): Boolean {
        val evidence = loadEvidence(evidenceId) ?: return false

        if (!verifyEvidenceIntegrity(evidence)) {
            return false
        }

        evidence.chainOfCustody.add(
            CustodyRecord(
                action = action,
                actor = actor,
                timestamp = System.currentTimeMillis(),
                location = "DEVICE",
                notes = notes
            )
        )

        evidence.hash = calculateEvidenceHash(evidence)
        saveEvidence(evidence)
        return true
    }

    fun verifyAllEvidence(): VerificationResult {
        val evidenceFiles = evidenceDir.listFiles() ?: return VerificationResult(false, emptyList())
        val results = evidenceFiles.map { file ->
            val evidence = gson.fromJson(file.readText(), ForensicEvidence::class.java)
            EvidenceVerification(evidence.id, verifyEvidenceIntegrity(evidence))
        }
        return VerificationResult(results.all { it.isValid }, results)
    }

    fun getAllEvidence(): List<ForensicEvidence> {
        val evidenceFiles = evidenceDir.listFiles() ?: return emptyList()
        return evidenceFiles.mapNotNull { file ->
            try {
                gson.fromJson(file.readText(), ForensicEvidence::class.java)
            } catch (e: Exception) {
                null
            }
        }
    }

    private fun saveEvidence(evidence: ForensicEvidence) {
        val file = File(evidenceDir, "${evidence.id}.json")
        file.writeText(gson.toJson(evidence))
    }

    fun loadEvidence(evidenceId: String): ForensicEvidence? {
        val file = File(evidenceDir, "$evidenceId.json")
        return if (file.exists()) {
            gson.fromJson(file.readText(), ForensicEvidence::class.java)
        } else {
            null
        }
    }

    private fun calculateEvidenceHash(evidence: ForensicEvidence): String {
        val evidenceString = gson.toJson(evidence.copy(hash = ""))
        return hashString(evidenceString)
    }

    private fun verifyEvidenceIntegrity(evidence: ForensicEvidence): Boolean {
        return calculateEvidenceHash(evidence) == evidence.hash
    }

    private fun hashString(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

class BlockchainLogger(private val context: Context) {
    private val gson = Gson()
    private val blockchainFile = File(context.filesDir, "forensic_blockchain.json")
    var blockchain: Blockchain = if (blockchainFile.exists()) {
        gson.fromJson(blockchainFile.readText(), Blockchain::class.java)
    } else {
        Blockchain(mutableListOf(createGenesisBlock()))
    }

    fun addBlock(action: String, data: String): Block {
        val previousBlock = blockchain.chain.last()
        val newBlock = Block(
            index = blockchain.chain.size,
            timestamp = System.currentTimeMillis(),
            action = action,
            data = data,
            previousHash = previousBlock.hash,
            hash = ""
        ).apply {
            hash = calculateBlockHash(this)
        }

        blockchain.chain.add(newBlock)
        saveBlockchain()
        return newBlock
    }

    fun verifyChain(): Boolean {
        if (blockchain.chain.isEmpty() || !isValidGenesisBlock(blockchain.chain[0])) {
            return false
        }

        for (i in 1 until blockchain.chain.size) {
            val currentBlock = blockchain.chain[i]
            val previousBlock = blockchain.chain[i - 1]

            if (currentBlock.previousHash != previousBlock.hash ||
                currentBlock.hash != calculateBlockHash(currentBlock)) {
                return false
            }
        }
        return true
    }

    fun getEvidenceLogs(evidenceId: String): List<Block> {
        return blockchain.chain.filter { it.data.contains(evidenceId) }
    }

    private fun createGenesisBlock(): Block {
        return Block(
            index = 0,
            timestamp = System.currentTimeMillis(),
            action = "GENESIS",
            data = "Initial forensic blockchain block",
            previousHash = "0",
            hash = ""
        ).apply {
            hash = calculateBlockHash(this)
        }
    }

    private fun isValidGenesisBlock(block: Block): Boolean {
        return block == createGenesisBlock()
    }

    fun calculateBlockHash(block: Block): String {
        val blockString = "${block.index}${block.timestamp}${block.action}${block.data}${block.previousHash}"
        return hashString(blockString)
    }

    private fun saveBlockchain() {
        blockchainFile.writeText(gson.toJson(blockchain))
    }

    private fun hashString(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

class ComplianceReporter(private val context: Context) {
    private val gson = Gson()
    private val evidenceManager = EvidenceManager(context)
    val blockchainLogger = BlockchainLogger(context)

    fun generateCombinedReport(): ComplianceReport {
        return ComplianceReport(
            timestamp = System.currentTimeMillis(),
            gdprCompliance = generateGDPRReport(),
            ccpaCompliance = generateCCPAReport(),
            issuesFound = emptyList(),
            recommendations = listOf(
                "Implementar borrado automático de datos según política de retención",
                "Documentar todos los procesos de tratamiento de datos personales",
                "Asegurar cifrado de todos los datos sensibles en reposo y tránsito"
            )
        )
    }

    fun generateGDPRReport(): GDPRCompliance {
        val evidence = evidenceManager.verifyAllEvidence()
        val chainValid = blockchainLogger.verifyChain()
        val issues = mutableListOf<String>()

        if (!evidence.allValid) issues.add("Evidencias con cadena de custodia comprometida")
        if (!chainValid) issues.add("Cadena de bloques de logs comprometida")

        val principles = mapOf(
            "Lawfulness" to checkLawfulness(),
            "Purpose limitation" to checkPurposeLimitation(),
            "Data minimization" to checkDataMinimization(),
            "Accuracy" to checkAccuracy(),
            "Storage limitation" to checkStorageLimitation(),
            "Integrity and confidentiality" to checkIntegrityAndConfidentiality(),
            "Accountability" to checkAccountability()
        )

        principles.forEach { (principle, compliant) ->
            if (!compliant) issues.add("Principle not compliant: $principle")
        }

        return GDPRCompliance(
            compliant = issues.isEmpty(),
            principles = principles,
            issues = issues,
            evidenceCount = countEvidenceByType(),
            lastVerification = System.currentTimeMillis()
        )
    }

    fun generateCCPAReport(): CCPACompliance {
        val issues = mutableListOf<String>()
        val rights = mapOf(
            "Right to know" to checkRightToKnow(),
            "Right to delete" to checkRightToDelete(),
            "Right to opt-out" to checkRightToOptOut(),
            "Right to non-discrimination" to checkRightToNonDiscrimination()
        )

        rights.forEach { (right, compliant) ->
            if (!compliant) issues.add("Right not guaranteed: $right")
        }

        return CCPACompliance(
            compliant = issues.isEmpty(),
            rights = rights,
            issues = issues,
            dataCollectionPractices = listOf(
                "Data collected for security and forensic purposes",
                "No sale of personal information"
            )
        )
    }

    private fun checkLawfulness(): Boolean {
        return getAllEvidence().all { evidence ->
            evidence.description.contains("lawful basis") ||
                    evidence.type == ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT
        }
    }

    private fun checkPurposeLimitation(): Boolean {
        return getAllEvidence().none { evidence ->
            evidence.description.contains("used for incompatible purpose")
        }
    }

    private fun checkDataMinimization(): Boolean {
        return getAllEvidence().none { evidence ->
            evidence.description.contains("excessive data") ||
                    (evidence.type == ForensicAnalysisSystem.EvidenceType.USER_ACTIVITY &&
                            !evidence.description.contains("authorized"))
        }
    }

    private fun checkAccuracy(): Boolean {
        return getAllEvidence()
            .filter { it.description.contains("personal data") }
            .all { evidence ->
                evidence.chainOfCustody.any {
                    it.action == "VERIFICATION" && it.notes.contains("accuracy confirmed")
                }
            }
    }

    private fun checkStorageLimitation(): Boolean {
        val retentionPolicyDays = 30
        val cutoff = System.currentTimeMillis() - (retentionPolicyDays * 24 * 60 * 60 * 1000L)
        return getAllEvidence().none { evidence ->
            evidence.chainOfCustody[0].timestamp < cutoff &&
                    evidence.description.contains("personal data")
        }
    }

    private fun checkIntegrityAndConfidentiality(): Boolean {
        return evidenceManager.verifyAllEvidence().allValid &&
                blockchainLogger.verifyChain()
    }

    private fun checkAccountability(): Boolean {
        return getAllEvidence().all { evidence ->
            evidence.chainOfCustody.isNotEmpty() &&
                    evidence.chainOfCustody.all { it.actor.isNotBlank() }
        }
    }

    private fun checkRightToKnow(): Boolean {
        return getAllEvidence().any { evidence ->
            evidence.type == ForensicAnalysisSystem.EvidenceType.USER_ACTIVITY &&
                    evidence.description.contains("data disclosure request")
        }
    }

    private fun checkRightToDelete(): Boolean {
        return getAllEvidence().any { evidence ->
            evidence.type == ForensicAnalysisSystem.EvidenceType.USER_ACTIVITY &&
                    evidence.description.contains("deletion request fulfilled")
        }
    }

    private fun checkRightToOptOut(): Boolean {
        return getAllEvidence().any { evidence ->
            evidence.type == ForensicAnalysisSystem.EvidenceType.USER_ACTIVITY &&
                    evidence.description.contains("opt-out mechanism")
        }
    }

    private fun checkRightToNonDiscrimination(): Boolean {
        return getAllEvidence().none { evidence ->
            evidence.description.contains("discrimination") ||
                    evidence.description.contains("retaliation")
        }
    }

    private fun countEvidenceByType(): Map<String, Int> {
        return getAllEvidence()
            .groupBy { it.type.name }
            .mapValues { it.value.size }
    }

    private fun getAllEvidence(): List<ForensicEvidence> {
        return evidenceManager.getAllEvidence()
    }
}

class IncidentInvestigator(private val context: Context) {
    private val evidenceManager = EvidenceManager(context)
    private val blockchainLogger = BlockchainLogger(context)

    fun investigate(incidentId: String): IncidentReport {
        val relatedEvidence = evidenceManager.getAllEvidence().filter {
            it.description.contains(incidentId) || it.source.contains(incidentId)
        }

        val relatedLogs = blockchainLogger.getEvidenceLogs(incidentId)
        val timeline = buildTimeline(relatedEvidence, relatedLogs)

        return IncidentReport(
            incidentId = incidentId,
            timestamp = System.currentTimeMillis(),
            relatedEvidence = relatedEvidence,
            relatedLogs = relatedLogs,
            timeline = timeline,
            findings = analyzeFindings(relatedEvidence, relatedLogs),
            recommendations = generateRecommendations(relatedEvidence)
        )
    }

    private fun buildTimeline(
        evidence: List<ForensicEvidence>,
        logs: List<Block>
    ): List<TimelineEvent> {
        val events = mutableListOf<TimelineEvent>()

        evidence.forEach { ev ->
            ev.chainOfCustody.forEach { custody ->
                events.add(
                    TimelineEvent(
                        timestamp = custody.timestamp,
                        type = "EVIDENCE_${custody.action}",
                        description = "${ev.type}: ${custody.notes}",
                        actor = custody.actor
                    )
                )
            }
        }

        logs.forEach { block ->
            events.add(
                TimelineEvent(
                    timestamp = block.timestamp,
                    type = "LOG_${block.action}",
                    description = block.data,
                    actor = "SYSTEM"
                )
            )
        }

        return events.sortedBy { it.timestamp }
    }

    private fun analyzeFindings(
        evidence: List<ForensicEvidence>,
        logs: List<Block>
    ): List<String> {
        val findings = mutableListOf<String>()

        if (evidence.any { it.type == ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT }) {
            findings.add("Eventos de seguridad detectados")
        }

        if (logs.any { it.action == "UNAUTHORIZED_ACCESS" }) {
            findings.add("Intentos de acceso no autorizados registrados")
        }

        if (evidence.any { it.type == ForensicAnalysisSystem.EvidenceType.UNAUTHORIZED_ACCESS }) {
            findings.add("Evidencia de acceso no autorizado confirmado")
        }

        return findings
    }

    private fun generateRecommendations(evidence: List<ForensicEvidence>): List<String> {
        val recommendations = mutableListOf<String>()

        if (evidence.any { it.type == ForensicAnalysisSystem.EvidenceType.UNAUTHORIZED_ACCESS }) {
            recommendations.add("Reforzar controles de autenticación")
            recommendations.add("Implementar monitoreo de accesos sospechosos")
        }

        if (evidence.any { it.type == ForensicAnalysisSystem.EvidenceType.SECURITY_EVENT }) {
            recommendations.add("Revisar políticas de seguridad")
            recommendations.add("Actualizar sistemas de detección de intrusiones")
        }

        return recommendations
    }
}

// Modelos de datos
data class ForensicEvidence(
    val id: String,
    val type: ForensicAnalysisSystem.EvidenceType,
    val description: String,
    val source: String,
    val creationDate: String,
    val collector: String,
    val chainOfCustody: MutableList<CustodyRecord>,
    var hash: String
)

data class CustodyRecord(
    val action: String,
    val actor: String,
    val timestamp: Long,
    val location: String,
    val notes: String
)

data class VerificationResult(
    val allValid: Boolean,
    val details: List<EvidenceVerification>
)

data class EvidenceVerification(
    val evidenceId: String,
    val isValid: Boolean
)

data class Blockchain(
    val chain: MutableList<Block>
)

data class Block(
    val index: Int,
    val timestamp: Long,
    val action: String,
    val data: String,
    val previousHash: String,
    var hash: String
)

data class ComplianceReport(
    val timestamp: Long,
    val gdprCompliance: GDPRCompliance,
    val ccpaCompliance: CCPACompliance,
    val issuesFound: List<String>,
    val recommendations: List<String>
)

data class GDPRCompliance(
    val compliant: Boolean,
    val principles: Map<String, Boolean>,
    val issues: List<String>,
    val evidenceCount: Map<String, Int>,
    val lastVerification: Long
)

data class CCPACompliance(
    val compliant: Boolean,
    val rights: Map<String, Boolean>,
    val issues: List<String>,
    val dataCollectionPractices: List<String>
)

data class IncidentReport(
    val incidentId: String,
    val timestamp: Long,
    val relatedEvidence: List<ForensicEvidence>,
    val relatedLogs: List<Block>,
    val timeline: List<TimelineEvent>,
    val findings: List<String>,
    val recommendations: List<String>
)

data class TimelineEvent(
    val timestamp: Long,
    val type: String,
    val description: String,
    val actor: String
)